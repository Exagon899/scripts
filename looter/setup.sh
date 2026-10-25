#!/usr/bin/env bash
# Self-contained setup: builds a local venv with all engines so CredHunter runs
# "out of the box". Cracking tools (hashcat/john) are intentionally NOT bundled
# (large binaries + GPU drivers); install them via your package manager and
# CredHunter will emit ready-to-crack hashes with the right hashcat -m mode.
set -e
cd "$(dirname "$0")"

echo "[*] creating venv ./venv"
python3 -m venv venv
# shellcheck disable=SC1091
source venv/bin/activate
pip install --upgrade pip wheel >/dev/null
echo "[*] installing engines (impacket, dploot, rich, pypykatz)"
pip install -r requirements.txt

# NetExec is not on PyPI; it is a CLI dependency. Warn (don't fail) if absent.
if ! command -v nxc >/dev/null 2>&1 && ! command -v netexec >/dev/null 2>&1; then
    echo "[!] nxc (NetExec) not found on PATH - the nxc/AD collectors will be skipped."
    echo "    install it with: pipx install git+https://github.com/Pennyw0rth/NetExec"
fi

echo
echo "[+] done. Run with:"
echo "    source venv/bin/activate"
echo "    ./looter.py -t <host> --cred 'DOMAIN/user:pass'"
echo
echo "[i] optional crackers (not bundled): sudo apt install hashcat john"
