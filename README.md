## 🦊 FoxPipe v1.9
Secure • Simple • Reliable Data Streaming
FoxPipe is a minimalist CLI utility for end-to-end encrypted and compressed data transfer between two machines.
------------------------------
## 🚀 Why FoxPipe?

* Simple
No accounts. Just a sender and a receiver.
* Efficient
Built-in zlib compression reduces bandwidth usage on the fly.
* Hardened Security
AES-256-GCM authenticated encryption + HMAC-SHA256 handshake verification.
* Safe
Includes safety caps (5GB default) and session timeouts to prevent resource abuse.

------------------------------
## 🛠️ Usage## 1️⃣ Receiver (Destination)
Start the receiver first. Use --public if you need to bind to all interfaces.

python3 foxpipe.py receive 8080 -p "secure-pass" > backup.sql

## 2️⃣ Sender (Source)

cat backup.sql | python3 foxpipe.py send 192.168.1.5 8080 -p "secure-pass"

------------------------------
## 📦 Advanced Features## Directory Transfer (Ultra Fast)
FoxPipe handles the compression internally now, but tar is still great for bundling:

# Source
tar -cf - ./project | python3 foxpipe.py send 1.2.3.4 9000 -p secret
# Destination
python3 foxpipe.py receive 9000 -p secret | tar -xf -

## Direct File Input
Instead of piping, you can use the --file flag:

python3 foxpipe.py send 1.2.3.4 8080 -p secret --file image.iso

------------------------------
## 🔒 Security Specs (v1.9)

* Encryption: AES-GCM (Authenticated Encryption).
* KDF: Scrypt ($N=2^{15}$) for high brute-force resistance.
* Handshake: HMAC-SHA256 verified session start (prevents data corruption from wrong passwords).
* Integrity: Tamper detection on every 64KB chunk.

------------------------------
## ⚠️ Safety Measures

* Max Chunk: 10MB (prevents memory overflow).
* Safety Cap: 5GB transfer limit (configurable in source).
* Timeouts: 15s connection / 300s session inactivity.

------------------------------
🦊 Build. Break. Secure.
