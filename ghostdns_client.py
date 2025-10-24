import socket
import struct
import base64
import logging
import os
import time
from typing import Tuple, Optional, List

try:
    from Crypto.Cipher import AES
    from Crypto.Protocol.KDF import PBKDF2
    from Crypto.Random import get_random_bytes
except Exception as e:
    raise SystemExit("PyCryptodome is required: pip install pycryptodome")

# ------------------------------------------------------------
# Logging
# ------------------------------------------------------------

def ghost_logger(name: str = "GhostDNS_Client", level: int = logging.INFO) -> logging.Logger:
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


def _b32_encode(data: bytes) -> str:
    return base64.b32encode(data).decode('ascii').strip('=')


def _b32_decode(text: str) -> bytes:
    pad_len = (8 - (len(text) % 8)) % 8
    padded = text + ('=' * pad_len)
    return base64.b32decode(padded.encode('ascii'))


def _chunk_labels(enc: str) -> List[str]:
    chunks = []
    while enc:
        chunk = enc[:DNS_MAX_LABEL]
        chunks.append(chunk.lower())
        enc = enc[DNS_MAX_LABEL:]
    return chunks


def _derive_key(secret: str, salt: bytes) -> bytes:
    return PBKDF2(secret, salt, dkLen=32, count=200_000)


def ghost_encode_payload(secret: str, plaintext: bytes) -> bytes:
    salt = get_random_bytes(16)
    key = _derive_key(secret, salt)
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
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
        if not label:
            continue
        out += struct.pack('B', len(label)) + label.encode('ascii')
    return out + b'\x00'


def _decode_qname(data: bytes, offset: int) -> Tuple[str, int]:
    labels = []
    orig = offset
    jumped = False
    while True:
        length = data[offset]
        if length & 0xC0 == 0xC0:
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

TYPE_A = 1
TYPE_TXT = 16
CLASS_IN = 1

# ------------------------------------------------------------
# Client implementation
# ------------------------------------------------------------

class GhostClient:
    def __init__(self, server_ip: str, port: int = 53, domain: str = 'ghost.local', secret: str = 'change_me', timeout: float = 3.0, retries: int = 3):
        self.server_ip = server_ip
        self.port = port
        self.domain = domain.strip('.')
        self.secret = secret
        self.timeout = timeout
        self.retries = retries
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(self.timeout)

    def _build_query_qname(self, blob: bytes) -> str:
        enc = _b32_encode(blob)
        labels = _chunk_labels(enc)
        # prefix to mark tunnel queries
        qname = '.'.join(['gh'] + labels + self.domain.split('.'))
        if len(qname) > DNS_MAX_NAME:
            raise ValueError('Encoded QNAME too long')
        return qname

    def _build_query_packet(self, txid: int, qname: str) -> bytes:
        flags = 0x0100  # standard query, recursion desired
        header = _build_dns_header(txid, flags, 1, 0, 0, 0)
        question = _encode_qname(qname) + struct.pack('!HH', TYPE_TXT, CLASS_IN)
        return header + question

    def _parse_txt_answers(self, resp: bytes) -> List[bytes]:
        txid, flags, qd, an, ns, ar = struct.unpack('!HHHHHH', resp[:12])
        offset = 12
        # skip question
        _, offset = _decode_qname(resp, offset)
        offset += 4  # qtype, qclass
        chunks: List[bytes] = []
        for _ in range(an):
            _, offset = _decode_qname(resp, offset)
            rtype, rclass, ttl, rdlen = struct.unpack('!HHLH', resp[offset:offset+10])
            offset += 10
            if rtype == TYPE_TXT:
                # TXT RDATA: one or more <len><data> fields; we take first
                if offset >= len(resp):
                    break
                txtlen = resp[offset]
                offset += 1
                txt = resp[offset:offset+txtlen]
                offset += txtlen
                chunks.append(txt)
            else:
                offset += rdlen
        return chunks

    def ghost_send_query(self, payload: bytes) -> Optional[bytes]:
        txid = int.from_bytes(os.urandom(2), 'big')
        blob = ghost_encode_payload(self.secret, payload)
        qname = self._build_query_qname(blob)
        pkt = self._build_query_packet(txid, qname)

        for attempt in range(1, self.retries + 1):
            try:
                logger.debug(f"Sending {len(pkt)} bytes to {self.server_ip}:{self.port} (attempt {attempt})")
                self.sock.sendto(pkt, (self.server_ip, self.port))
                resp = self.ghost_receive_response()
                if resp is None:
                    raise TimeoutError('No response payload')
                return resp
            except (socket.timeout, TimeoutError) as e:
                logger.warning(f"Timeout waiting for response (attempt {attempt})")
                continue
            except Exception as e:
                logger.error(f"Error sending query: {e}")
                break
        return None

    def ghost_receive_response(self) -> Optional[bytes]:
        try:
            resp, _ = self.sock.recvfrom(4096)
            chunks = self._parse_txt_answers(resp)
            if not chunks:
                return None
            b32 = b''.join(chunks).decode('ascii')
            enc_blob = _b32_decode(b32)
            plaintext = ghost_decode_payload(self.secret, enc_blob)
            return plaintext
        except Exception as e:
            logger.debug(f"Receive error: {e}")
            return None

    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass

# ------------------------------------------------------------
# CLI
# ------------------------------------------------------------

def main():
    import argparse
    parser = argparse.ArgumentParser(description='GhostDNS Client')
    parser.add_argument('--server', required=True, help='GhostDNS server IP')
    parser.add_argument('--port', type=int, default=53)
    parser.add_argument('--domain', default='ghost.local')
    parser.add_argument('--secret', default='change_me')
    parser.add_argument('--message', help='Message to send')
    parser.add_argument('--file', help='Small file to send')
    parser.add_argument('--cmd', help='Execute command on server (test)')
    parser.add_argument('--retries', type=int, default=3)
    parser.add_argument('--timeout', type=float, default=3.0)
    parser.add_argument('--debug', action='store_true')
    args = parser.parse_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)

    gc = GhostClient(server_ip=args.server, port=args.port, domain=args.domain, secret=args.secret, timeout=args.timeout, retries=args.retries)

    try:
        if args.cmd:
            data = b'CMD:' + args.cmd.encode('utf-8')
            logger.info(f"Sending command: {args.cmd}")
            resp = gc.ghost_send_query(data)
        elif args.file:
            with open(args.file, 'rb') as f:
                data = f.read()
            logger.info(f"Sending file {args.file} ({len(data)} bytes)")
            resp = gc.ghost_send_query(data)
        else:
            data = (args.message or 'hello from client').encode('utf-8')
            logger.info(f"Sending message: {data[:64]!r} ({len(data)} bytes)")
            resp = gc.ghost_send_query(data)
        if resp is None:
            logger.error('No response received')
        else:
            logger.info(f"Response ({len(resp)} bytes): {resp[:256]!r}")
            try:
                print(resp.decode('utf-8', 'ignore'))
            except Exception:
                print(resp)
    finally:
        gc.close()


if __name__ == '__main__':
    main()
