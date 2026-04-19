#!/usr/bin/env python3
"""
FoxPipe v1.4 - Secure • Simple • Reliable Data Streaming
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
CHUNK_SIZE = 4096
MAGIC = b"FOXPIPE"
VERSION = 1
TOOL_VERSION = "1.4"

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
        salt + MAGIC + bytes([VERSION]) + bytes([flags]),
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
    print(f"FoxPipe v{TOOL_VERSION} | Mode: SEND", file=sys.stderr)

    try:
        source = open(file_path, "rb") if file_path else sys.stdin.buffer
    except Exception as e:
        print(f"[-] Cannot open file: {e}", file=sys.stderr)
        sys.exit(1)

    flags = FLAG_COMPRESS

    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            sock.settimeout(TIMEOUT)

            salt = secrets.token_bytes(16)
            key = derive_key(password, salt)
            aes = AESGCM(key)

            # Handshake
            sock.sendall(MAGIC + bytes([VERSION]) + bytes([flags]))
            sock.sendall(salt)
            sock.sendall(auth_tag(key, salt, flags))

            print(f"[+] Connected to {host}:{port}", file=sys.stderr)
            print("[+] Sending data...", file=sys.stderr)

            total = 0
            start = time.time()
            last_activity = time.time()

            while True:
                if time.time() - last_activity > SESSION_TIMEOUT:
                    print("\n[-] Session timeout (idle)", file=sys.stderr)
                    return

                chunk = source.read(CHUNK_SIZE)
                if not chunk:
                    break

                compressed = zlib.compress(chunk)
                if (flags & FLAG_COMPRESS) and len(compressed) < len(chunk):
                    payload = b"\x01" + compressed
                else:
                    payload = b"\x00" + chunk

                encrypted = encrypt_data(aes, payload)
                sock.sendall(len(encrypted).to_bytes(4, "big") + encrypted)

                total += len(chunk)
                last_activity = time.time()

                elapsed = time.time() - start
                speed = (total / 1024) / elapsed if elapsed > 0 else 0

                print(f"\r[>] {total/1024:.2f} KB | {speed:.2f} KB/s",
                      end="", file=sys.stderr)

            sock.sendall((0).to_bytes(4, "big"))
            sock.shutdown(socket.SHUT_WR)

            duration = time.time() - start
            mbps = (total/1024/1024)/duration if duration > 0 else 0

            print("\n[+] Transfer complete", file=sys.stderr)
            print(f"[+] {total/1024/1024:.2f} MB in {duration:.2f}s ({mbps:.2f} MB/s)",
                  file=sys.stderr)

    except ConnectionRefusedError:
        print("\n[-] Connection refused", file=sys.stderr)
        print("[!] Start receiver first:", file=sys.stderr)
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
    print(f"FoxPipe v{TOOL_VERSION} | Mode: RECEIVE", file=sys.stderr)
    print("[i] Start this FIRST, then run sender", file=sys.stderr)

    bind_addr = "0.0.0.0" if public else "127.0.0.1"

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((bind_addr, port))
            sock.listen(1)

            print(f"[+] Listening on {bind_addr}:{port}", file=sys.stderr)

            conn, addr = sock.accept()
            conn.settimeout(TIMEOUT)

            with conn:
                print(f"[+] Connection from {addr}", file=sys.stderr)

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
                    print("[-] Authentication failed", file=sys.stderr)
                    return

                aes = AESGCM(key)

                total = 0
                start = time.time()
                last_activity = time.time()

                while True:
                    if time.time() - last_activity > SESSION_TIMEOUT:
                        print("\n[-] Session timeout", file=sys.stderr)
                        return

                    length = int.from_bytes(recv_exact(conn, 4), "big")

                    if length == 0:
                        break

                    if length <= 0 or length > MAX_CHUNK:
                        print("[-] Invalid packet size", file=sys.stderr)
                        return

                    data = recv_exact(conn, length)

                    try:
                        decrypted = decrypt_data(aes, data)

                        flag = decrypted[0]
                        body = decrypted[1:]

                        if flag == 1:
                            output = zlib.decompress(body, max_length=MAX_CHUNK)
                        else:
                            output = body

                        sys.stdout.buffer.write(output)
                        sys.stdout.buffer.flush()

                        total += len(output)
                        last_activity = time.time()

                        elapsed = time.time() - start
                        speed = (total / 1024) / elapsed if elapsed > 0 else 0

                        print(f"\r[<] {total/1024:.2f} KB | {speed:.2f} KB/s",
                              end="", file=sys.stderr)

                    except Exception as e:
                        print(f"\n[-] Processing failed: {e}", file=sys.stderr)
                        return

                duration = time.time() - start
                mbps = (total/1024/1024)/duration if duration > 0 else 0

                print("\n[+] Receive complete", file=sys.stderr)
                print(f"[+] {total/1024/1024:.2f} MB in {duration:.2f}s ({mbps:.2f} MB/s)",
                      file=sys.stderr)

    except Exception as e:
        print(f"\n[-] Receiver error: {e}", file=sys.stderr)
        sys.exit(1)

# =========================
# MAIN
# =========================
def main():
    parser = argparse.ArgumentParser(description="FoxPipe - Secure Data Streaming")

    subparsers = parser.add_subparsers(dest="mode", required=True)

    send_parser = subparsers.add_parser("send")
    send_parser.add_argument("host")
    send_parser.add_argument("port", type=int)
    send_parser.add_argument("-p", "--password")
    send_parser.add_argument("--file")

    recv_parser = subparsers.add_parser("receive")
    recv_parser.add_argument("port", type=int)
    recv_parser.add_argument("-p", "--password")
    recv_parser.add_argument("--public", action="store_true")

    args = parser.parse_args()

    password = args.password or getpass.getpass("Enter shared password: ")
    if not password.strip():
        print("[-] Password required", file=sys.stderr)
        sys.exit(1)

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
        print("\n[!] Interrupted by user. Closing.", file=sys.stderr)
        sys.exit(130)