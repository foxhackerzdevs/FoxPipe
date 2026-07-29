#!/usr/bin/env python3
"""
FoxPipe v2.0 - Secure • Simple • Reliable Data Streaming

v2.0: replaces the v1 password-hash handshake (vulnerable to offline
dictionary attacks, no forward secrecy) with SPAKE2 PAKE + ephemeral
X25519 key exchange + explicit key confirmation. See handshake_client()
/ handshake_server() below. Not wire-compatible with v1 by design --
a version mismatch fails cleanly rather than silently downgrading.
"""

import socket
import argparse
import sys
import secrets
import time
import hmac
import hashlib
import getpass
import zlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

try:
    from spake2 import SPAKE2_Symmetric
except ImportError:
    sys.exit("[-] Missing dependency: pip install spake2")

# =========================
# CONFIG
# =========================
CHUNK_SIZE = 65536
MAGIC = b"FOXPIPE"
VERSION = 2
TOOL_VERSION = "2.0"

FLAG_COMPRESS = 0b00000001

MAX_CHUNK = 10_000_000
TIMEOUT = 15
SESSION_TIMEOUT = 300

PAKE_ID = b"foxpipe-v2-pake"
HKDF_INFO = b"foxpipe-v2-session-derivation"
CONFIRM_LABEL_CLIENT = b"foxpipe-v2-confirm-client"
CONFIRM_LABEL_SERVER = b"foxpipe-v2-confirm-server"

SPAKE2_MSG_LEN = 33
X25519_PUBKEY_LEN = 32
CONFIRM_TAG_LEN = 32


# =========================
# PAKE HANDSHAKE
# =========================
def _derive_master_key(pake_key, dh_secret):
    hkdf = HKDF(algorithm=hashes.SHA256(), length=64, salt=pake_key, info=HKDF_INFO)
    master = hkdf.derive(dh_secret)
    return master[:32], master[32:]  # K_payload, K_confirm


def handshake_client(sock, password):
    """
    Client (sender) side of the v2 handshake. Returns AESGCM(K_payload)
    on success, or raises ConnectionError with a clear message on
    authentication failure -- never proceeds to stream data on mismatch.
    """
    sp = SPAKE2_Symmetric(password.encode(), idSymmetric=PAKE_ID)
    pake_msg = sp.start()
    eph_priv = x25519.X25519PrivateKey.generate()
    eph_pub_bytes = eph_priv.public_key().public_bytes_raw()

    sock.sendall(pake_msg + eph_pub_bytes)
    peer_blob = recv_exact(sock, SPAKE2_MSG_LEN + X25519_PUBKEY_LEN)
    peer_pake_msg = peer_blob[:SPAKE2_MSG_LEN]
    peer_pub_bytes = peer_blob[SPAKE2_MSG_LEN:]

    pake_key = sp.finish(peer_pake_msg)
    dh_secret = eph_priv.exchange(x25519.X25519PublicKey.from_public_bytes(peer_pub_bytes))
    k_payload, k_confirm = _derive_master_key(pake_key, dh_secret)

    own_confirm = hmac.new(k_confirm, CONFIRM_LABEL_CLIENT, hashlib.sha256).digest()
    sock.sendall(own_confirm)
    peer_confirm = recv_exact(sock, CONFIRM_TAG_LEN)
    expected_peer_confirm = hmac.new(k_confirm, CONFIRM_LABEL_SERVER, hashlib.sha256).digest()

    if not hmac.compare_digest(peer_confirm, expected_peer_confirm):
        raise ConnectionError("Authentication failed (wrong password or MITM)")

    return AESGCM(k_payload)


def handshake_server(sock, password):
    """Server (receiver) side of the v2 handshake. See handshake_client()."""
    sp = SPAKE2_Symmetric(password.encode(), idSymmetric=PAKE_ID)
    pake_msg = sp.start()
    eph_priv = x25519.X25519PrivateKey.generate()
    eph_pub_bytes = eph_priv.public_key().public_bytes_raw()

    peer_blob = recv_exact(sock, SPAKE2_MSG_LEN + X25519_PUBKEY_LEN)
    peer_pake_msg = peer_blob[:SPAKE2_MSG_LEN]
    peer_pub_bytes = peer_blob[SPAKE2_MSG_LEN:]
    sock.sendall(pake_msg + eph_pub_bytes)

    pake_key = sp.finish(peer_pake_msg)
    dh_secret = eph_priv.exchange(x25519.X25519PublicKey.from_public_bytes(peer_pub_bytes))
    k_payload, k_confirm = _derive_master_key(pake_key, dh_secret)

    peer_confirm = recv_exact(sock, CONFIRM_TAG_LEN)
    own_confirm = hmac.new(k_confirm, CONFIRM_LABEL_SERVER, hashlib.sha256).digest()
    sock.sendall(own_confirm)
    expected_peer_confirm = hmac.new(k_confirm, CONFIRM_LABEL_CLIENT, hashlib.sha256).digest()

    if not hmac.compare_digest(peer_confirm, expected_peer_confirm):
        raise ConnectionError("Authentication failed (wrong password or MITM)")

    return AESGCM(k_payload)


# =========================
# ENCRYPT / DECRYPT
# =========================
def encrypt_data(aes, data):
    nonce = secrets.token_bytes(12)
    return nonce + aes.encrypt(nonce, data, None)


def decrypt_data(aes, data):
    nonce = data[:12]
    return aes.decrypt(nonce, data[12:], None)


# =========================
# SOCKET UTIL
# =========================
def recv_exact(conn, n):
    data = b""
    while len(data) < n:
        chunk = conn.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Connection closed unexpectedly")
        data += chunk
    return data


# =========================
# SAFE DECOMPRESSION
# =========================
def safe_decompress_stream(decompressor, data, limit):
    out = decompressor.decompress(data, limit)
    if decompressor.unconsumed_tail:
        raise ValueError("Decompression exceeded safe limit")
    return out


# =========================
# SENDER
# =========================
def send_data(host, port, password, file_path=None, compress=True):
    print(f"FoxPipe v{TOOL_VERSION} | SEND", file=sys.stderr)

    try:
        source = open(file_path, "rb") if file_path else sys.stdin.buffer
    except Exception as e:
        sys.exit(f"[-] File error: {e}")

    flags = FLAG_COMPRESS if compress else 0
    session_id = secrets.token_bytes(8)

    compressor = zlib.compressobj() if compress else None

    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            sock.settimeout(TIMEOUT)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

            # Handshake
            sock.sendall(MAGIC + bytes([VERSION]) + bytes([flags]))
            sock.sendall(session_id)
            aes = handshake_client(sock, password)

            print(f"[+] Connected → {host}:{port}", file=sys.stderr)

            total = 0
            start = time.time()
            last = time.time()

            while True:
                if time.time() - last > SESSION_TIMEOUT:
                    sys.exit("\n[-] Session timeout")

                chunk = source.read(CHUNK_SIZE)
                if not chunk:
                    break

                payload = compressor.compress(chunk) if compress else chunk

                if payload:
                    encrypted = encrypt_data(aes, payload)
                    sock.sendall(len(encrypted).to_bytes(4, "big") + encrypted)

                total += len(chunk)
                last = time.time()

                elapsed = time.time() - start
                speed = (total / 1024) / elapsed if elapsed else 0

                print(f"\r[>] {total/1024:.2f} KB | {speed:.2f} KB/s",
                      end="", file=sys.stderr)

            # Flush compression
            if compress:
                final = compressor.flush()
                if final:
                    encrypted = encrypt_data(aes, final)
                    sock.sendall(len(encrypted).to_bytes(4, "big") + encrypted)

            sock.sendall((0).to_bytes(4, "big"))
            sock.shutdown(socket.SHUT_WR)

            print("\n[+] Done", file=sys.stderr)

    except Exception as e:
        sys.exit(f"\n[-] Sender error: {e}")

    finally:
        if file_path:
            source.close()


# =========================
# RECEIVER
# =========================
def receive_data(port, password, public, max_gb):
    print(f"FoxPipe v{TOOL_VERSION} | RECEIVE", file=sys.stderr)
    print("[i] Start this FIRST, then run sender", file=sys.stderr)

    bind = "0.0.0.0" if public else "127.0.0.1"
    max_total = max_gb * 1024 * 1024 * 1024
    decompressor = zlib.decompressobj()

    try:
        with socket.socket() as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((bind, port))
            sock.listen(1)

            print(f"[+] Listening on {bind}:{port}", file=sys.stderr)

            conn, addr = sock.accept()
            conn.settimeout(TIMEOUT)
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

            with conn:
                print(f"[+] Connected ← {addr}", file=sys.stderr)

                header = recv_exact(conn, len(MAGIC) + 2)

                if header[:len(MAGIC)] != MAGIC:
                    sys.exit("[-] Invalid protocol")

                version = header[len(MAGIC)]
                flags = header[len(MAGIC) + 1]

                if version != VERSION:
                    sys.exit("[-] Version mismatch")

                session_id = recv_exact(conn, 8)
                try:
                    aes = handshake_server(conn, password)
                except ConnectionError as e:
                    sys.exit(f"[-] {e}")

                total = 0
                start = time.time()

                while True:
                    length = int.from_bytes(recv_exact(conn, 4), "big")

                    if length == 0:
                        break

                    if length <= 0 or length > MAX_CHUNK:
                        sys.exit("[-] Invalid size")

                    data = recv_exact(conn, length)
                    decrypted = decrypt_data(aes, data)

                    if flags & FLAG_COMPRESS:
                        output = safe_decompress_stream(decompressor, decrypted, MAX_CHUNK)
                    else:
                        output = decrypted

                    if output:
                        sys.stdout.buffer.write(output)
                        sys.stdout.buffer.flush()
                        total += len(output)

                    if total > max_total:
                        sys.exit("\n[-] Transfer exceeded safety limit")

                    elapsed = time.time() - start
                    speed = (total / 1024) / elapsed if elapsed else 0

                    print(f"\r[<] {total/1024:.2f} KB | {speed:.2f} KB/s",
                          end="", file=sys.stderr)

                # Final flush
                if flags & FLAG_COMPRESS:
                    remaining = decompressor.flush()
                    if remaining:
                        sys.stdout.buffer.write(remaining)
                        sys.stdout.buffer.flush()

                print("\n[+] Done", file=sys.stderr)

    except Exception as e:
        sys.exit(f"\n[-] Receiver error: {e}")


# =========================
# MAIN
# =========================
def main():
    parser = argparse.ArgumentParser(description="FoxPipe")
    parser.add_argument('--version', action='version', version=f'FoxPipe {TOOL_VERSION}')

    sub = parser.add_subparsers(dest="mode", required=True)

    s = sub.add_parser("send")
    s.add_argument("host")
    s.add_argument("port", type=int)
    s.add_argument("-p", "--password")
    s.add_argument("--file")
    s.add_argument("--no-compress", action="store_true")

    r = sub.add_parser("receive")
    r.add_argument("port", type=int)
    r.add_argument("-p", "--password")
    r.add_argument("--public", action="store_true")
    r.add_argument("--limit", type=int, default=5, help="Total GB limit (default: 5)")

    args = parser.parse_args()

    password = args.password or getpass.getpass("Password: ")
    if not password.strip():
        sys.exit("[-] Password required")

    if args.mode == "send":
        send_data(
            args.host,
            args.port,
            password,
            args.file,
            compress=not args.no_compress
        )
    else:
        receive_data(args.port, password, args.public, args.limit)


# =========================
# ENTRY
# =========================
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted", file=sys.stderr)
        sys.exit(130)
