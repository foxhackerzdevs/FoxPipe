#!/usr/bin/env python3

import socket
import argparse
import sys
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
import secrets

CHUNK_SIZE = 4096

# =========================
# KEY DERIVATION
# =========================
def derive_key(password, salt):
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# =========================
# ENCRYPTION
# =========================
def encrypt_data(key, data):
    aes = AESGCM(key)
    nonce = secrets.token_bytes(12)
    encrypted = aes.encrypt(nonce, data, None)
    return nonce + encrypted

def decrypt_data(key, data):
    aes = AESGCM(key)
    nonce = data[:12]
    ciphertext = data[12:]
    return aes.decrypt(nonce, ciphertext, None)

# =========================
# SENDER
# =========================
def send_data(host, port, password):
    sock = socket.socket()
    sock.connect((host, port))

    salt = secrets.token_bytes(16)
    key = derive_key(password, salt)

    sock.sendall(salt)

    print(f"[+] Connected to {host}:{port}")
    print("[+] Sending data...")

    while True:
        chunk = sys.stdin.buffer.read(CHUNK_SIZE)
        if not chunk:
            break
        encrypted = encrypt_data(key, chunk)
        sock.sendall(len(encrypted).to_bytes(4, 'big') + encrypted)

    print("[+] Transfer complete")
    sock.close()

# =========================
# RECEIVER
# =========================
def receive_data(port, password):
    sock = socket.socket()
    sock.bind(("0.0.0.0", port))
    sock.listen(1)

    print(f"[+] Listening on port {port}...")

    conn, addr = sock.accept()
    print(f"[+] Connection from {addr}")

    salt = conn.recv(16)
    key = derive_key(password, salt)

    while True:
        length_bytes = conn.recv(4)
        if not length_bytes:
            break

        length = int.from_bytes(length_bytes, 'big')

        data = b""
        while len(data) < length:
            data += conn.recv(length - len(data))

        decrypted = decrypt_data(key, data)
        sys.stdout.buffer.write(decrypted)
        sys.stdout.buffer.flush()

    print("\n[+] Receive complete")
    conn.close()

# =========================
# CLI
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

    args = parser.parse_args()

    if args.mode == "send":
        send_data(args.host, args.port, args.password)

    elif args.mode == "receive":
        receive_data(args.port, args.password)

    else:
        parser.print_help()

if __name__ == "__main__":
    main()