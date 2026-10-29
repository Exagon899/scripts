#!/bin/sh
# nixdump setup: optional venv for rich + a check of the external crackers.
# nixdump itself runs on pure stdlib; none of this is required to loot, only to
# get the pretty table (rich) and offline cracking (--crack).
set -e

HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"

echo "[*] setting up python venv (for rich table output)"
python3 -m venv venv 2>/dev/null || true
if [ -f venv/bin/activate ]; then
    . venv/bin/activate
    pip install -q --upgrade pip >/dev/null 2>&1 || true
    pip install -q -r requirements.txt >/dev/null 2>&1 || \
        pip install -q --break-system-packages -r requirements.txt >/dev/null 2>&1 || true
fi

echo "[*] external tool check (optional, used only when present):"
for t in john hashcat ssh2john keepass2john firefox_decrypt; do
    if command -v "$t" >/dev/null 2>&1; then
        echo "    [OK]      $t"
    else
        echo "    [missing] $t"
    fi
done

echo
echo "[*] run:   python3 nixdump.py            (loot)"
echo "[*] crack: python3 nixdump.py --crack    (needs john + wordlist)"
