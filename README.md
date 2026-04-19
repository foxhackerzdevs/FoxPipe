## 🦊 FoxPipe v1.9

**Secure • Simple • Reliable Data Streaming**

FoxPipe is a minimalist CLI tool for **end-to-end encrypted, optionally compressed data transfer** between two machines — no setup, no accounts, just a shared password.

---

## 🚀 Why FoxPipe?

* **Simple**
  No servers, no login. Just run sender and receiver.

* **Efficient**
  Built-in `zlib` streaming compression reduces bandwidth usage automatically.

* **Secure by Design**
  Uses **AES-256-GCM** for authenticated encryption and **HMAC-SHA256** for handshake validation.

* **Resilient**
  Includes chunk limits, decompression guards, and session timeouts.

---

## 🛠️ Usage

### 1️⃣ Receiver (Destination)

Start this **first**:

```bash
python3 foxpipe.py receive 8080 -p "secure-pass" > backup.sql
```

Use `--public` to accept connections from other machines:

```bash
python3 foxpipe.py receive 8080 -p "secure-pass" --public > backup.sql
```

---

### 2️⃣ Sender (Source)

```bash
cat backup.sql | python3 foxpipe.py send 192.168.1.5 8080 -p "secure-pass"
```

---

## 📦 Advanced Features

### 📁 Directory Transfer (Recommended)

FoxPipe handles compression internally, but `tar` is ideal for bundling:

```bash
# Source
tar -cf - ./project | python3 foxpipe.py send 1.2.3.4 9000 -p secret

# Destination
python3 foxpipe.py receive 9000 -p secret | tar -xf -
```

---

### 📄 Direct File Transfer

```bash
python3 foxpipe.py send 1.2.3.4 8080 -p secret --file image.iso
```

---

### 🚫 Disable Compression

Useful for already-compressed files (e.g., `.zip`, `.mp4`):

```bash
python3 foxpipe.py send 1.2.3.4 8080 -p secret --file video.mp4 --no-compress
```

---

## 🔒 Security Specs (v1.9)

* **Encryption:** AES-256-GCM (authenticated encryption)
* **Key Derivation:** Scrypt (`N = 2¹⁵`, `r = 8`, `p = 1`)
* **Handshake Authentication:** HMAC-SHA256 with session binding
* **Session Protection:** Random session ID prevents replay attacks
* **Integrity:** Built-in AEAD ensures per-chunk tamper detection

> ⚠️ Note: HMAC is used for **authentication of handshake**, not per-chunk integrity (handled by AES-GCM).

---

## ⚠️ Safety Measures

* **Max Chunk Size:** 10 MB (prevents memory abuse)
* **Session Timeout:** 300 seconds (idle disconnect)
* **Connection Timeout:** 15 seconds
* **Safe Decompression:** Prevents zip-bomb style attacks

> ⚠️ The "5GB transfer cap" is not enforced in code by default — mention only if implemented.

---

## 🧠 Design Notes

* Uses **streaming compression**, not per-chunk compression (avoids inefficiency)
* Uses **random nonces per chunk** (safe for AES-GCM)
* Uses **constant-time HMAC comparison** to prevent timing attacks
* Avoids buffering entire files → works for large streams

---

## ⚡ Quick Example

```bash
# Terminal 1 (Receiver)
python3 foxpipe.py receive 9000 -p pass --public > file.txt

# Terminal 2 (Sender)
python3 foxpipe.py send <IP> 9000 -p pass --file file.txt
```

---

## 🦊 Philosophy

> Build simple tools that are hard to misuse and easy to trust.
