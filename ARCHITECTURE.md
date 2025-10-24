# Architecture and Protocol

## Overview
GhostDNS tunnels encrypted payloads through DNS queries and answers.

- Client embeds data into the QNAME of a TXT query.
- Server replies with TXT records carrying the encrypted response.
- AES-256-GCM provides confidentiality and integrity.

## Packet format
- Encrypted blob: `v1 | salt(16) | nonce(12) | tag(16) | ciphertext`
- Inner plaintext prefix: `ts(4 bytes) | rnd(2 bytes) | user_data...`

## DNS layer
- Query: QTYPE=TXT.
- QNAME: `gh.<b32-chunks>.<domain>`
  - Base32 (RFC 4648) uppercase alphabet, transmitted lowercase labels.
  - Labels <= 63 chars; full name <= 253 chars.
- Response: one or more TXT answers, each containing up to 255 bytes of Base32 text.

## Flow
1. Client encrypts payload with fresh `salt` (PBKDF2 key derivation) and `nonce` per message.
2. Client base32-encodes encrypted blob and constructs QNAME.
3. Server decodes, decrypts, processes payload, constructs a response payload (e.g., `ACK:<data>` or command output), encrypts, splits into TXT chunks, and responds.
4. Client parses TXT answers, reassembles the Base32 text, decrypts, and returns the plaintext.

## Concurrency and reliability
- Server is UDP-based; each incoming query is handled in a thread.
- No fragmentation/reassembly logic is implemented yet; keep payloads small.
- Client has retry and timeout controls.

## Security considerations
- AES-GCM ensures authenticity and confidentiality of payloads.
- PBKDF2 (200k iterations) derives a 256-bit key from a shared secret and random salt.
- Optional HMAC can be added in a future version for layered integrity or alternate KDF contexts.
- DNS metadata (who is talking to whom, when) remains visible.

## Extensibility
- Add session IDs and sequence numbers for multi-packet streams.
- Implement fragmentation of payloads across multiple queries.
- Add transport fallbacks (DoT/DoH) in separate modules while reusing crypto/encoding.
