# Quickstart

This guide shows you how to run GhostDNS fast on Windows and Linux. Android (Termux) notes included.

## Prerequisites
- Python 3.14+
- PyCryptodome: `pip install pycryptodome`
- Firewall rules allowing UDP on your chosen port (53 or 5353)

## 1) Start the server

Windows (without Administrator, use unprivileged port 5353):
```powershell
python .\ghostdns_server.py --bind 0.0.0.0 --port 5353 --secret "S3cr3t!" --domain ghost.local --debug
```

Windows (with Administrator, port 53):
```powershell
python .\ghostdns_server.py --bind 0.0.0.0 --port 53 --secret "S3cr3t!" --domain ghost.local
```

Linux (root for port 53, or pick 5353):
```bash
sudo python3 ./ghostdns_server.py --bind 0.0.0.0 --port 53 --secret "S3cr3t!" --domain ghost.local
```

## 2) Run the client

On the same machine (127.0.0.1) or a different host (server LAN IP):

Send a message:
```powershell
python .\ghostdns_client.py --server 127.0.0.1 --port 5353 --secret "S3cr3t!" --domain ghost.local --message "hello server" --debug
```

Run a test command on the server:
```powershell
python .\ghostdns_client.py --server 127.0.0.1 --port 5353 --secret "S3cr3t!" --cmd "whoami"
```

Send a small file:
```powershell
python .\ghostdns_client.py --server 127.0.0.1 --port 5353 --secret "S3cr3t!" --file "C:\\path\\to\\file.bin"
```

Note: If your server uses port 53 instead of 5353, set `--port 53` on the client.

## Troubleshooting
- Timeouts: open firewall for UDP, confirm IP/port, increase `--timeout` and `--retries`.
- Decrypt errors: make sure `--secret` and `--domain` match on both sides.
- Encoded QNAME too long: payload too large; send smaller data; fragmentation is a potential future enhancement.
