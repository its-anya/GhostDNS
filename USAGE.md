# Usage and CLI Reference

This document details all command-line options and common scenarios.

## Server: `ghostdns_server.py`

```text
--bind <ip>        Bind IP (default: 0.0.0.0)
--port <int>       UDP port (default: 53)
--secret <str>     Shared secret (AES-256-GCM)
--domain <str>     Domain suffix to match (default: ghost.local)
--debug            Enable debug logging
```

Examples:
```powershell
# Unprivileged port
python .\ghostdns_server.py --bind 0.0.0.0 --port 5353 --secret "S3cr3t!" --domain ghost.local --debug

# Port 53 (Admin/root)
python .\ghostdns_server.py --bind 0.0.0.0 --port 53 --secret "S3cr3t!" --domain ghost.local
```

## Client: `ghostdns_client.py`

```text
--server <ip>      Server IP (required)
--port <int>       UDP port (default: 53)
--domain <str>     Domain suffix (default: ghost.local)
--secret <str>     Shared secret (must match server)
--message <str>    Send a text message
--file <path>      Send a small file
--cmd <str>        Execute command on server (test)
--retries <int>    Retries on timeout (default: 3)
--timeout <sec>    Socket timeout seconds (default: 3.0)
--debug            Debug logging
```

Examples:
```powershell
# Send a message
python .\ghostdns_client.py --server 127.0.0.1 --port 5353 --secret "S3cr3t!" --domain ghost.local --message "hello server" --debug

# Execute command on server
python .\ghostdns_client.py --server 127.0.0.1 --port 5353 --secret "S3cr3t!" --cmd "whoami"

# Send a small file
python .\ghostdns_client.py --server 127.0.0.1 --port 5353 --secret "S3cr3t!" --file "C:\\path\\to\\file.bin"
```

## What happens under the hood
- Client encrypts payload with AES-256-GCM: `v1 | salt(16) | nonce(12) | tag(16) | ciphertext`.
- Base32-encodes the blob and splits into DNS labels (<=63 chars), prefixed with `gh`:
  - QNAME: `gh.<b32-chunks>.ghost.local` (for example)
- Sends a DNS TXT query to the server.
- Server extracts Base32 from QNAME, decrypts, and produces a response payload.
- Server encrypts response similarly and returns Base32 text in TXT RDATA.
- Client parses TXT answers, concatenates Base32 strings, decodes, and decrypts.

## Limits and guidelines
- DNS label limit: 63 chars per label; total name length ~253 chars.
- TXT chunk: up to 255 bytes per string; multiple TXT RRs used if needed.
- Payload size: best for short messages/command outputs; large data may exceed limits.
- Reliability: UDP can drop packets; client retries are configurable.

## Security notes
- Use a strong secret and rotate periodically.
- DNS traffic is visible on the network; AEAD protects content but not metadata.
- Only run `--cmd` for testing in trusted environments; output size is capped to ~1200 bytes.
