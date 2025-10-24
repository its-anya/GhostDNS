# GhostDNS

GhostDNS is a DNS tunneling system written in Python. It tunnels small messages or files inside DNS queries and responses. A client embeds encrypted payloads into DNS QNAME labels and sends TXT queries; the server extracts, decrypts, processes, and replies with encrypted TXT records.

- Transport: UDP (default port 53; configurable)
- Encoding: Base32 in QNAME/TXT
- Encryption: AES-256-GCM with PBKDF2 key derivation
- Cross-platform: Windows, Linux; client runs on Android (Termux)

## Components
- `ghostdns_server.py`: UDP DNS server that decodes and responds to tunneled queries.
- `ghostdns_client.py`: Client that encrypts/encodes payloads and sends DNS TXT queries.

## When to use GhostDNS
- Lab/research: learn DNS tunneling, AEAD encryption, and label packing.
- Restricted networks: when direct protocols are blocked but DNS is allowed (authorized testing only).
- Lightweight remote command tests: quickly return outputs such as `whoami`, `ipconfig`.
- Small file/message transfer.

## Safety and legality
GhostDNS is for authorized environments only (lab, internal testing, with permission). Misuse can be illegal. AES-GCM gives confidentiality and integrity, but DNS is observable; do not assume stealth against monitoring.

## Getting started
- Install Python 3.14+.
- Install dependency: `pip install pycryptodome`.
- Start the server, then run the client with the same `--secret` and `--domain`.

See `QUICKSTART.md` and `USAGE.md` for commands and examples, and `ARCHITECTURE.md` for internals.
