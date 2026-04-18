#!/usr/bin/env python3

import socket
import argparse
import sys
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend

CHUNK_SIZE = 4096
MAGIC = b"FOXPIPE1"
MAX_CHUNK = 10_000_000  # 10 MB safety limit

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
# ENCRYPT / DECRYPT
# =========================
def encrypt_data(aes, data):
    nonce = secrets.token_bytes(12)
    encrypted = aes.encrypt(nonce, data, None)
    return nonce + encrypted

def decrypt_data(aes, data):
    nonce = data[:12]
    ciphertext = data[12:]
    return aes.decrypt(nonce, ciphertext, None)

# =========================
# SOCKET UTILS
# =========================
def recv_exact(conn, n):
    data = b""
    while len(data) < n:
        chunk = conn.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data

# =========================
# SENDER
# =========================
def send_data(host, port, password):
    try:
        with socket.create_connection((host, port)) as sock:
            salt = secrets.token_bytes(16)
            key = derive_key(password, salt)
            aes = AESGCM(key)

            # Handshake
            sock.sendall(MAGIC)
            sock.sendall(salt)

            print(f"[+] Connected to {host}:{port}", file=sys.stderr)
            print("[+] Sending data...", file=sys.stderr)

            total_sent = 0

            while True:
                chunk = sys.stdin.buffer.read(CHUNK_SIZE)
                if not chunk:
                    break

                encrypted = encrypt_data(aes, chunk)
                sock.sendall(len(encrypted).to_bytes(4, "big") + encrypted)

                total_sent += len(chunk)
                print(f"\r[>] Sent: {total_sent / 1024:.2f} KB", end="", file=sys.stderr)

            # EOF marker
            sock.sendall((0).to_bytes(4, "big"))

            print("\n[+] Transfer complete", file=sys.stderr)

    except Exception as e:
        print(f"\n[-] Sender error: {e}", file=sys.stderr)

# =========================
# RECEIVER
# =========================
def receive_data(port, password, public):
    try:
        bind_addr = "0.0.0.0" if public else "127.0.0.1"

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((bind_addr, port))
            sock.listen(1)

            print(f"[+] Listening on {bind_addr}:{port}...", file=sys.stderr)
            conn, addr = sock.accept()

            with conn:
                print(f"[+] Connection from {addr}", file=sys.stderr)

                # Handshake validation
                magic = recv_exact(conn, len(MAGIC))
                if magic != MAGIC:
                    print("[-] Invalid client", file=sys.stderr)
                    return

                salt = recv_exact(conn, 16)
                if salt is None:
                    print("[-] Failed to receive salt", file=sys.stderr)
                    return

                key = derive_key(password, salt)
                aes = AESGCM(key)

                total_received = 0

                while True:
                    length_bytes = recv_exact(conn, 4)
                    if length_bytes is None:
                        break

                    length = int.from_bytes(length_bytes, "big")

                    # EOF
                    if length == 0:
                        break

                    # Safety check
                    if length <= 0 or length > MAX_CHUNK:
                        print("[-] Invalid packet size", file=sys.stderr)
                        return

                    data = recv_exact(conn, length)
                    if data is None:
                        break

                    try:
                        decrypted = decrypt_data(aes, data)
                        sys.stdout.buffer.write(decrypted)
                        sys.stdout.buffer.flush()

                        total_received += len(decrypted)
                        print(f"\r[<] Received: {total_received / 1024:.2f} KB", end="", file=sys.stderr)

                    except Exception:
                        print("\n[-] Decryption failed! Check your password.", file=sys.stderr)
                        return

                print("\n[+] Receive complete", file=sys.stderr)

    except Exception as e:
        print(f"\n[-] Receiver error: {e}", file=sys.stderr)

# =========================
# MAIN
# =========================
def main():
    parser = argparse.ArgumentParser(description="FoxPipe - Secure Data Streaming")
    subparsers = parser.add_subparsers(dest="mode")

    send_parser = subparsers.add_parser("send")
    send_parser.add_argument("host")
    send_parser.add_argument("port", type=int)
    send_parser.add_argument("-p", "--password", required=True)

    recv_parser = subparsers.add_parser("receive")
    recv_parser.add_argument("port", type=int)
    recv_parser.add_argument("-p", "--password", required=True)
    recv_parser.add_argument("--public", action="store_true", help="Bind to 0.0.0.0")

    args = parser.parse_args()

    if args.mode == "send":
        send_data(args.host, args.port, args.password)
    elif args.mode == "receive":
        receive_data(args.port, args.password, args.public)
    else:
        parser.print_help()

# =========================
# ENTRY
# =========================
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user. Closing.", file=sys.stderr)
        sys.exit(130)