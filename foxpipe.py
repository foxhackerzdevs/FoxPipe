#!/usr/bin/env python3
"""
FoxPipe v1.8 - Secure • Simple • Reliable Data Streaming
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
TOOL_VERSION = "1.8"

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
                    print("\n[-] Session timeout", file=sys.stderr)
                    return

                chunk = source.read(CHUNK_SIZE)
                if not chunk:
                    break

                if compress:
                    comp = compressor.compress(chunk)
                    payload = b"\x01" + comp if comp else b"\x00" + chunk
                else:
                    payload = b"\x00" + chunk

                encrypted = encrypt_data(aes, payload)
                sock.sendall(len(encrypted).to_bytes(4, "big") + encrypted)

                total += len(chunk)
                last = time.time()

                elapsed = time.time() - start
                speed = (total / 1024) / elapsed if elapsed else 0

                print(f"\r[>] {total/1024:.2f} KB | {speed:.2f} KB/s",
                      end="", file=sys.stderr)

            # Flush compression stream
            if compress:
                final = compressor.flush()
                if final:
                    encrypted = encrypt_data(aes, b"\x01" + final)
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
def receive_data(port, password, public):
    print(f"FoxPipe v{TOOL_VERSION} | RECEIVE", file=sys.stderr)
    print("[i] Start this FIRST, then run sender", file=sys.stderr)

    bind = "0.0.0.0" if public else "127.0.0.1"
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
                    print("[-] Invalid protocol", file=sys.stderr)
                    return

                version = header[len(MAGIC)]
                flags = header[len(MAGIC) + 1]

                if version != VERSION:
                    print("[-] Version mismatch", file=sys.stderr)
                    return

                session_id = recv_exact(conn, 8)
                salt = recv_exact(conn, 16)

                key = derive_key(password, salt)

                recv_tag = recv_exact(conn, 32)
                if not hmac.compare_digest(
                    recv_tag,
                    auth_tag(key, salt, flags, session_id)
                ):
                    print("[-] Auth failed", file=sys.stderr)
                    return

                aes = AESGCM(key)

                total = 0
                start = time.time()

                while True:
                    length = int.from_bytes(recv_exact(conn, 4), "big")

                    if length == 0:
                        break

                    if length <= 0 or length > MAX_CHUNK:
                        print("[-] Invalid size", file=sys.stderr)
                        return

                    data = recv_exact(conn, length)
                    decrypted = decrypt_data(aes, data)

                    if len(decrypted) < 1:
                        print("[-] Invalid packet", file=sys.stderr)
                        return

                    flag = decrypted[0]
                    body = decrypted[1:]

                    if not (flags & FLAG_COMPRESS):
                        flag = 0

                    if flag == 1:
                        output = safe_decompress_stream(decompressor, body, MAX_CHUNK)
                    else:
                        output = body

                    sys.stdout.buffer.write(output)
                    sys.stdout.buffer.flush()

                    total += len(output)

                    elapsed = time.time() - start
                    speed = (total / 1024) / elapsed if elapsed else 0

                    print(f"\r[<] {total/1024:.2f} KB | {speed:.2f} KB/s",
                          end="", file=sys.stderr)

                print("\n[+] Done", file=sys.stderr)

    except Exception as e:
        sys.exit(f"\n[-] Receiver error: {e}")


# =========================
# MAIN
# =========================
def main():
    parser = argparse.ArgumentParser(description="FoxPipe")

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
        receive_data(args.port, password, args.public)


# =========================
# ENTRY
# =========================
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted", file=sys.stderr)
        sys.exit(130)