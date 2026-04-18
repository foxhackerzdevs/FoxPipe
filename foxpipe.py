#!/usr/bin/env python3
"""
FoxPipe - Secure • Simple • Reliable Data Streaming
End-to-end encrypted data transfer that works like a Unix pipe.

Usage:
  Receiver: python3 foxpipe.py receive 8080 > file
  Sender:   cat file | python3 foxpipe.py send 1.2.3.4 8080
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
MAX_CHUNK = 10_000_000  # 10MB - prevents memory exhaustion
TIMEOUT = 15  # seconds

# =========================
# KEY DERIVATION
# =========================
def derive_key(password, salt):
    """Derive a 256-bit key from password + salt using Scrypt."""
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**15,  # ~200ms on modern CPU, good brute-force resistance
        r=8,
        p=1,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# =========================
# AUTH TAG - MITM PROTECTION
# =========================
def auth_tag(key, salt):
    """HMAC to prove both sides derived the same key before sending data."""
    return hmac.new(key, salt, hashlib.sha256).digest()

# =========================
# ENCRYPT / DECRYPT
# =========================
def encrypt_data(aes, data):
    """Encrypt chunk with AES-GCM. Fresh 12-byte nonce per chunk."""
    nonce = secrets.token_bytes(12)
    encrypted = aes.encrypt(nonce, data, None)
    return nonce + encrypted

def decrypt_data(aes, data):
    """Decrypt chunk with AES-GCM. Verifies auth tag automatically."""
    nonce = data[:12]
    ciphertext = data[12:]
    return aes.decrypt(nonce, ciphertext, None)

# =========================
# SAFE RECEIVE
# =========================
def recv_exact(conn, n):
    """Receive exactly n bytes or raise. Prevents silent truncation."""
    data = b""
    while len(data) < n:
        chunk = conn.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Connection closed early")
        data += chunk
    return data

# =========================
# SENDER
# =========================
def send_data(host, port, password):
    """Stream stdin to remote host with authenticated encryption."""
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            sock.settimeout(TIMEOUT)

            salt = secrets.token_bytes(16)
            key = derive_key(password, salt)
            aes = AESGCM(key)

            # Handshake: magic + version + salt + HMAC(key, salt)
            sock.sendall(MAGIC + VERSION)
            sock.sendall(salt)
            sock.sendall(auth_tag(key, salt))

            print(f"[+] Connected to {host}:{port}", file=sys.stderr)
            print("[+] Sending data...", file=sys.stderr)

            total_sent = 0
            start = time.time()

            while True:
                chunk = sys.stdin.buffer.read(CHUNK_SIZE)
                if not chunk:
                    break

                encrypted = encrypt_data(aes, chunk)
                # Frame: 4-byte big-endian length + nonce|ciphertext|tag
                sock.sendall(len(encrypted).to_bytes(4, "big") + encrypted)

                total_sent += len(chunk)
                elapsed = time.time() - start
                speed = (total_sent / 1024) / elapsed if elapsed > 0 else 0
                print(f"\r[>] {total_sent/1024:.2f} KB | {speed:.2f} KB/s", end="", file=sys.stderr)

            # EOF marker: 0-length chunk
            sock.sendall((0).to_bytes(4, "big"))
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
    """Listen for FoxPipe connection and stream decrypted data to stdout."""
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

                # Verify handshake
                header = recv_exact(conn, len(MAGIC) + 1)
                if not header.startswith(MAGIC) or header[-1:] != VERSION:
                    print("[-] Invalid protocol or version mismatch", file=sys.stderr)
                    return

                salt = recv_exact(conn, 16)
                key = derive_key(password, salt)

                # Constant-time HMAC check prevents timing attacks
                recv_tag = recv_exact(conn, 32)
                if not hmac.compare_digest(recv_tag, auth_tag(key, salt)):
                    print("[-] Authentication failed. Wrong password?", file=sys.stderr)
                    return

                aes = AESGCM(key)
                total_received = 0
                start = time.time()

                while True:
                    length_bytes = recv_exact(conn, 4)
                    length = int.from_bytes(length_bytes, "big")

                    if length == 0:  # EOF marker
                        break

                    if length <= 0 or length > MAX_CHUNK:
                        print("[-] Invalid packet size", file=sys.stderr)
                        return

                    data = recv_exact(conn, length)

                    try:
                        decrypted = decrypt_data(aes, data)
                        sys.stdout.buffer.write(decrypted)
                        sys.stdout.buffer.flush()

                        total_received += len(decrypted)
                        elapsed = time.time() - start
                        speed = (total_received / 1024) / elapsed if elapsed > 0 else 0
                        print(f"\r[<] {total_received/1024:.2f} KB | {speed:.2f} KB/s", end="", file=sys.stderr)

                    except Exception:
                        print("\n[-] Decryption failed! Wrong password or corrupted data.", file=sys.stderr)
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
        description="FoxPipe - Secure Data Streaming",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Receive to file
  python3 foxpipe.py receive 9000 > backup.tar.gz

  # Send a file
  cat backup.tar.gz | python3 foxpipe.py send 203.0.113.10 9000

  # Pipe a directory
  tar czf - ./project | python3 foxpipe.py send 1.2.3.4 9000
  python3 foxpipe.py receive 9000 | tar xzf -
"""
    )

    subparsers = parser.add_subparsers(dest="mode", required=True)

    send_parser = subparsers.add_parser("send", help="Send stdin to remote FoxPipe")
    send_parser.add_argument("host", help="Receiver IP or hostname")
    send_parser.add_argument("port", type=int, help="Receiver port")
    send_parser.add_argument("-p", "--password", help="Pre-shared password. Omit to prompt securely.")

    recv_parser = subparsers.add_parser("receive", help="Receive FoxPipe stream to stdout")
    recv_parser.add_argument("port", type=int, help="Port to listen on")
    recv_parser.add_argument("-p", "--password", help="Pre-shared password. Omit to prompt securely.")
    recv_parser.add_argument("--public", action="store_true", 
                           help="Listen on 0.0.0.0 instead of 127.0.0.1")

    args = parser.parse_args()

    # Prompt for password if not provided - avoids leaking to `ps` or history
    password = args.password or getpass.getpass("Password: ")
    if not password:
        print("[-] Password cannot be empty", file=sys.stderr)
        sys.exit(1)

    if args.mode == "send":
        send_data(args.host, args.port, password)
    elif args.mode == "receive":
        receive_data(args.port, password, args.public)

# =========================
# ENTRY
# =========================
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted.", file=sys.stderr)
        sys.exit(130)