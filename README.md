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
Uses **AES-256-GCM** for authenticated encryption and **Scrypt** for strong key derivation.

**Resilient**
Includes chunk limits, decompression guards, session validation, and timeouts.

---

## 🛠️ Usage

### 1️⃣ Receiver (Destination)

Start this **first**:

```bash
python3 foxpipe.py receive 8080 -p "secure-pass" > backup.sql
```

Allow connections from other machines:

```bash
python3 foxpipe.py receive 8080 -p "secure-pass" --public > backup.sql
```

---

### 2️⃣ Sender (Source)

```bash
cat backup.sql | python3 foxpipe.py send 192.168.1.5 8080 -p "secure-pass"
```

---

## 📦 Advanced Usage

### 📁 Directory Transfer (Recommended)

Use `tar` for structured transfer:

```bash
# Sender
tar -cf - ./project | python3 foxpipe.py send 1.2.3.4 9000 -p secret

# Receiver
python3 foxpipe.py receive 9000 -p secret | tar -xf -
```

---

### 📄 Direct File Transfer

```bash
python3 foxpipe.py send 1.2.3.4 8080 -p secret --file image.iso
```

---

### 🚫 Disable Compression

For already compressed files (`.zip`, `.mp4`, etc.):

```bash
python3 foxpipe.py send 1.2.3.4 8080 -p secret --file video.mp4 --no-compress
```

---

## 🔒 Security Model (v1.9)

* **Encryption:** AES-256-GCM (authenticated encryption per chunk)
* **Key Derivation:** Scrypt (`N=2¹⁵`, `r=8`, `p=1`)
* **Handshake Authentication:** HMAC-SHA256
* **Session Binding:** Random session ID prevents replay across sessions
* **Integrity:** Provided by AES-GCM (no separate MAC needed per chunk)

> ⚠️ Note: HMAC is used only during handshake authentication.

---

## ⚠️ Safety Measures

* **Max Chunk Size:** 10 MB
* **Max Transfer Size:** 5 GB (enforced)
* **Session Timeout:** 300 seconds (idle)
* **Connection Timeout:** 15 seconds
* **Safe Streaming Decompression:** Prevents zip-bomb style attacks

---

## 🧠 Design Notes

* Uses **streaming compression** (not per-chunk compression)
* Uses **random nonce per chunk** (safe for AES-GCM)
* Uses **constant-time HMAC comparison**
* Avoids buffering entire files → supports large transfers
* Minimal protocol: low overhead, easy to audit

---

## ⚡ Quick Example

```bash
# Receiver
python3 foxpipe.py receive 9000 -p pass --public > file.txt

# Sender
python3 foxpipe.py send <IP> 9000 -p pass --file file.txt
```

---

## ⚠️ Limitations

* Single connection only (no multi-client support)
* No resume support (yet)
* No file metadata (name/size must be handled externally)

---

## 🦊 Philosophy

> Build simple tools that are hard to misuse and easy to trust.
