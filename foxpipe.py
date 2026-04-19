#!/usr/bin/env python3
"""
FoxPipe v1.5 - Secure • Simple • Reliable Data Streaming
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
TOOL_VERSION = "1.5"

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
def auth_tag(key, salt, flags):
    return hmac.new(
        key,
        salt + MAGIC + bytes([VERSION]) + bytes([flags]) + b"FOXPIPE_AUTH",
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
# SAFE RECEIVE
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
# SENDER
# =========================
def send_data(host, port, password, file_path=None):
    print(f"FoxPipe v{TOOL_VERSION} | SEND", file=sys.stderr)

    try:
        source = open(file_path, "rb") if file_path else sys.stdin.buffer
    except Exception as e:
        print(f"[-] File error: {e}", file=sys.stderr)
        sys.exit(1)

    flags = FLAG_COMPRESS
    compressor = zlib.compressobj()

    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            sock.settimeout(TIMEOUT)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

            salt = secrets.token_bytes(16)
            key = derive_key(password, salt)
            aes = AESGCM(key)

            # Handshake
            sock.sendall(MAGIC + bytes([VERSION]) + bytes([flags]))
            sock.sendall(salt)
            sock.sendall(auth_tag(key, salt, flags))

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

                compressed = compressor.compress(chunk)

                if compressed:
                    payload = b"\x01" + compressed
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

            # Flush compressor
            final = compressor.flush()
            if final:
                payload = b"\x01" + final
                encrypted = encrypt_data(aes, payload)
                sock.sendall(len(encrypted).to_bytes(4, "big") + encrypted)

            sock.sendall((0).to_bytes(4, "big"))
            sock.shutdown(socket.SHUT_WR)

            print("\n[+] Done", file=sys.stderr)

    except ConnectionRefusedError:
        print("\n[-] Connection refused", file=sys.stderr)
        print("[!] Start receiver first", file=sys.stderr)
        sys.exit(2)

    except Exception as e:
        print(f"\n[-] Sender error: {e}", file=sys.stderr)
        sys.exit(1)

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

                salt = recv_exact(conn, 16)
                key = derive_key(password, salt)

                recv_tag = recv_exact(conn, 32)
                if not hmac.compare_digest(recv_tag, auth_tag(key, salt, flags)):
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

                    try:
                        decrypted = decrypt_data(aes, data)

                        if not decrypted:
                            continue

                        flag = decrypted[0]
                        body = decrypted[1:]

                        if flag == 1:
                            output = decompressor.decompress(body, MAX_CHUNK)
                        else:
                            output = body

                        sys.stdout.buffer.write(output)
                        sys.stdout.buffer.flush()

                        total += len(output)

                        elapsed = time.time() - start
                        speed = (total / 1024) / elapsed if elapsed else 0

                        print(f"\r[<] {total/1024:.2f} KB | {speed:.2f} KB/s",
                              end="", file=sys.stderr)

                    except Exception as e:
                        print(f"\n[-] Error: {e}", file=sys.stderr)
                        return

                print("\n[+] Done", file=sys.stderr)

    except Exception as e:
        print(f"\n[-] Receiver error: {e}", file=sys.stderr)
        sys.exit(1)

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

    r = sub.add_parser("receive")
    r.add_argument("port", type=int)
    r.add_argument("-p", "--password")
    r.add_argument("--public", action="store_true")

    args = parser.parse_args()

    password = args.password or getpass.getpass("Password: ")
    if not password.strip():
        sys.exit("[-] Password required")

    if args.mode == "send":
        send_data(args.host, args.port, password, args.file)
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