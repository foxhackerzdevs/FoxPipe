#!/usr/bin/env python3
"""
FoxPipe v1.9 - Secure • Simple • Reliable Data Streaming
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
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend

# =========================
# CONFIG
# =========================
CHUNK_SIZE = 65536
MAGIC = b"FOXPIPE"
VERSION = 1
TOOL_VERSION = "1.9"

FLAG_COMPRESS = 0b00000001

MAX_CHUNK = 10_000_000
TIMEOUT = 15
SESSION_TIMEOUT = 300


# =========================
# KEY DERIVATION
# =========================
def derive_key(password, salt):
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**15,
        r=8,
        p=1,
        backend=default_backend()
    )
    return kdf.derive(password.encode())


# =========================
# AUTH TAG
# =========================
def auth_tag(key, salt, flags, session_id):
    return hmac.new(
        key,
        salt + session_id + MAGIC + bytes([VERSION]) + bytes([flags]),
        hashlib.sha256
    ).digest()


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

            salt = secrets.token_bytes(16)
            key = derive_key(password, salt)
            aes = AESGCM(key)

            # Handshake
            sock.sendall(MAGIC + bytes([VERSION]) + bytes([flags]))
            sock.sendall(session_id)
            sock.sendall(salt)
            sock.sendall(auth_tag(key, salt, flags, session_id))

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
                salt = recv_exact(conn, 16)

                key = derive_key(password, salt)

                recv_tag = recv_exact(conn, 32)
                if not hmac.compare_digest(
                    recv_tag,
                    auth_tag(key, salt, flags, session_id)
                ):
                    sys.exit("[-] Authentication failed")

                aes = AESGCM(key)

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