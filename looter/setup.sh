#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip wheel >/dev/null
pip install -r requirements.txt
echo "[+] done. source venv/bin/activate && ./looter.py -t <host> --cred 'DOMAIN/user:pass'"
