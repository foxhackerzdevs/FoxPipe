#!/usr/bin/env python3
"""
FoxPipe - Secure • Simple • Reliable Data Streaming
End-to-end encrypted data transfer like a Unix pipe.
"""

import socket
import argparse
import sys
import secrets
import time
import hmac
import hashlib
import getpass
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend

CHUNK_SIZE = 4096
MAGIC = b"FOXPIPE"
VERSION = b"\x01"
MAX_CHUNK = 10_000_000
TIMEOUT = 15

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
# AUTH TAG (ANTI-MITM)
# =========================
def auth_tag(key, salt):
    return hmac.new(key, salt, hashlib.sha256).digest()

# =========================
# ENCRYPT / DECRYPT
# =========================
def encrypt_data(aes, data):
    # Fresh nonce per chunk (CRITICAL for GCM safety)
    nonce = secrets.token_bytes(12)
    encrypted = aes.encrypt(nonce, data, None)
    return nonce + encrypted

def decrypt_data(aes, data):
    nonce = data[:12]
    ciphertext = data[12:]
    return aes.decrypt(nonce, ciphertext, None)

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
def send_data(host, port, password):
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            sock.settimeout(TIMEOUT)

            salt = secrets.token_bytes(16)
            key = derive_key(password, salt)
            aes = AESGCM(key)

            # Handshake
            sock.sendall(MAGIC + VERSION)
            sock.sendall(salt)
            sock.sendall(auth_tag(key, salt))

            print(f"[+] Connected to {host}:{port}", file=sys.stderr)
            print("[+] Sending data...", file=sys.stderr)

            total = 0
            start = time.time()

            while True:
                chunk = sys.stdin.buffer.read(CHUNK_SIZE)
                if not chunk:
                    break

                encrypted = encrypt_data(aes, chunk)
                sock.sendall(len(encrypted).to_bytes(4, "big") + encrypted)

                total += len(chunk)
                elapsed = time.time() - start
                speed = (total / 1024) / elapsed if elapsed > 0 else 0
                print(f"\r[>] {total/1024:.2f} KB | {speed:.2f} KB/s",
                      end="", file=sys.stderr)

            # EOF marker
            sock.sendall((0).to_bytes(4, "big"))

            # Graceful shutdown
            sock.shutdown(socket.SHUT_WR)

            print("\n[+] Transfer complete", file=sys.stderr)

    except BrokenPipeError:
        print("\n[-] Receiver disconnected early", file=sys.stderr)
    except Exception as e:
        print(f"\n[-] Sender error: {e}", file=sys.stderr)
        sys.exit(1)

# =========================
# RECEIVER
# =========================
def receive_data(port, password, public):
    bind_addr = "0.0.0.0" if public else "127.0.0.1"

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((bind_addr, port))
            sock.listen(1)

            print(f"[+] Listening on {bind_addr}:{port}...", file=sys.stderr)
            conn, addr = sock.accept()
            conn.settimeout(TIMEOUT)

            with conn:
                print(f"[+] Connection from {addr}", file=sys.stderr)

                # Validate protocol
                header = recv_exact(conn, len(MAGIC) + 1)
                if not header.startswith(MAGIC) or header[-1:] != VERSION:
                    print("[-] Invalid protocol/version", file=sys.stderr)
                    return

                salt = recv_exact(conn, 16)
                key = derive_key(password, salt)

                recv_tag = recv_exact(conn, 32)
                if not hmac.compare_digest(recv_tag, auth_tag(key, salt)):
                    print("[-] Authentication failed", file=sys.stderr)
                    return

                aes = AESGCM(key)
                total = 0
                start = time.time()

                while True:
                    length = int.from_bytes(recv_exact(conn, 4), "big")

                    if length == 0:
                        break

                    if length <= 0 or length > MAX_CHUNK:
                        print("[-] Invalid packet size", file=sys.stderr)
                        return

                    data = recv_exact(conn, length)

                    try:
                        decrypted = decrypt_data(aes, data)
                        sys.stdout.buffer.write(decrypted)
                        sys.stdout.buffer.flush()

                        total += len(decrypted)
                        elapsed = time.time() - start
                        speed = (total / 1024) / elapsed if elapsed > 0 else 0
                        print(f"\r[<] {total/1024:.2f} KB | {speed:.2f} KB/s",
                              end="", file=sys.stderr)

                    except Exception:
                        print("\n[-] Decryption failed", file=sys.stderr)
                        return

                print("\n[+] Receive complete", file=sys.stderr)

    except Exception as e:
        print(f"\n[-] Receiver error: {e}", file=sys.stderr)
        sys.exit(1)

# =========================
# MAIN
# =========================
def main():
    parser = argparse.ArgumentParser(
        description="FoxPipe - Secure Data Streaming"
    )

    subparsers = parser.add_subparsers(dest="mode", required=True)

    send_parser = subparsers.add_parser("send")
    send_parser.add_argument("host")
    send_parser.add_argument("port", type=int)
    send_parser.add_argument("-p", "--password")

    recv_parser = subparsers.add_parser("receive")
    recv_parser.add_argument("port", type=int)
    recv_parser.add_argument("-p", "--password")
    recv_parser.add_argument("--public", action="store_true")

    args = parser.parse_args()

    password = args.password or getpass.getpass("Password: ")
    if not password:
        print("[-] Password required", file=sys.stderr)
        sys.exit(1)

    if args.mode == "send":
        send_data(args.host, args.port, password)
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