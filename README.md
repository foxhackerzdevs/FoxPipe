## 🦊 FoxPipe v1.9

**Secure • Simple • Reliable Data Streaming**

FoxPipe is a minimalist CLI tool for **end-to-end encrypted, optionally compressed data transfer** between two machines — no setup, no accounts, just a shared password.

---

## 🚀 Why FoxPipe?

**Simple**
No servers, no login. Just run sender and receiver.

**Efficient**
Built-in `zlib` streaming compression reduces bandwidth usage automatically.

**Secure by Design**
Uses **AES-256-GCM (AEAD)** for encryption and **Scrypt** for strong key derivation.

**Resilient**
Includes chunk limits, decompression guards, session validation, and timeouts.

---

## 📥 Installation

Install directly from PyPI:
```bash
pip install foxpipe
```

---

## 🛠️ Usage

### 1️⃣ Receiver (Destination)

Start this **first**:

```bash
foxpipe receive 8080 -p "secure-pass" > backup.sql
```

Allow external connections:

```bash
foxpipe receive 8080 -p "secure-pass" --public > backup.sql
```

---

### 2️⃣ Sender (Source)

```bash
cat backup.sql | foxpipe send 192.168.1.5 8080 -p "secure-pass"
```

---

## 📦 Advanced Usage

### 📁 Directory Transfer (Recommended)

```bash
# Sender
tar -cf - ./project | foxpipe send 1.2.3.4 9000 -p secret

# Receiver
foxpipe receive 9000 -p secret | tar -xf -
```

---

### 📄 Direct File Transfer

```bash
foxpipe send 1.2.3.4 8080 -p secret --file image.iso
```

---

### 🚫 Disable Compression

For already compressed files:

```bash
foxpipe send 1.2.3.4 8080 -p secret --file video.mp4 --no-compress
```

---

## 🔒 Security Model (v1.9)

* **Encryption:** AES-256-GCM (authenticated encryption per chunk)
* **Key Derivation:** Scrypt (`N=2¹⁵`, `r=8`, `p=1`)
* **Handshake Authentication:** HMAC-SHA256
* **Session Binding:** Random session ID prevents replay across sessions
* **Integrity & Authenticity:** Provided by AES-GCM (AEAD)

> ⚠️ HMAC is used only for handshake authentication, not for data chunks.

---

## ⚠️ Safety Measures

* **Max Chunk Size:** 10 MB
* **Session Timeout:** 300 seconds (idle)
* **Connection Timeout:** 15 seconds
* **Safe Streaming Decompression:** Protects against zip-bomb style attacks
* **DoS Protection:** Receiver enforces a global transfer limit (default **5GB**). 
  Adjust using `--limit` (e.g., `--limit 100` for 100GB).

---

## 🧠 Design Notes

* Uses **streaming compression (single zlib stream)**
* Uses **random nonce per chunk** (safe for AES-GCM usage)
* Uses **constant-time HMAC comparison**
* Avoids buffering entire files → supports large transfers
* Minimal protocol → low overhead, easy to audit

---

## ⚡ Quick Example

```bash
# Receiver
foxpipe receive 9000 -p pass --public > file.txt

# Sender
foxpipe send <IP> 9000 -p pass --file file.txt
```

---

## ⚠️ Limitations

* Single connection only
* No resume support
* No file metadata (name/size handled externally)

---

## 🦊 Philosophy

> Build simple tools that are hard to misuse and easy to trust.
