#!/usr/bin/env python3

import socket
import argparse
import sys
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend

CHUNK_SIZE = 4096

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

def recv_exact(conn, n):
    data = b""
    while len(data) < n:
        chunk = conn.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data

def send_data(host, port, password):
    with socket.create_connection((host, port)) as sock:
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
            sock.sendall(len(encrypted).to_bytes(4, "big") + encrypted)

        print("[+] Transfer complete")

def receive_data(port, password):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("0.0.0.0", port))
        sock.listen(1)

        print(f"[+] Listening on port {port}...")
        conn, addr = sock.accept()

        with conn:
            print(f"[+] Connection from {addr}")

            salt = recv_exact(conn, 16)
            if salt is None:
                print("[-] Failed to receive salt")
                return

            key = derive_key(password, salt)

            while True:
                length_bytes = recv_exact(conn, 4)
                if length_bytes is None:
                    break

                length = int.from_bytes(length_bytes, "big")
                data = recv_exact(conn, length)
                if data is None:
                    break

                try:
                    decrypted = decrypt_data(key, data)
                except Exception:
                    print("[-] Decryption failed")
                    return

                sys.stdout.buffer.write(decrypted)
                sys.stdout.buffer.flush()

            print("\n[+] Receive complete")

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