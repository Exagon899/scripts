# moorloot
Domain-joined Windows credential looter (MVP). Orchestrates impacket/dploot/nxc,
tries a credential pool against each host, auto-decrypts browser/DPAPI secrets,
one unified table.

## Run
./setup.sh && source venv/bin/activate
./looter.py -t <host> --cred 'DOMAIN/user:pass' --cred 'DOMAIN/user2#<nthash>' --json
./looter.py --list
