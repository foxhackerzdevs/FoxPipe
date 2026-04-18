## 🦊 FoxPipe

**Secure • Simple • Reliable Data Streaming**

FoxPipe is a minimalist CLI utility for **end-to-end encrypted data transfer** between two machines.

It follows a simple idea:

> Moving data should feel like using a Unix pipe—without compromising security.

---

## 🚀 Why FoxPipe?

* **Simple**
  No accounts. No cloud. No setup. Just a sender and a receiver.

* **Practical**
  Pipe anything—archives, database dumps, backups, or live logs.

* **Secure**
  AES-256-GCM authenticated encryption with Scrypt-based key derivation.

* **Clean**
  Progress logs go to `stderr`, keeping `stdout` pure for piping.

---

## 🛠️ Usage

### 1️⃣ Receiver (Destination)

```bash
python3 foxpipe.py receive 8080 -p "your-secure-password" > received_data.zip
```

---

### 2️⃣ Sender (Source)

```bash
cat large_file.zip | python3 foxpipe.py send 192.168.1.5 8080 -p "your-secure-password"
```

---

## 📦 Advanced: Transfer Directories

### Source

```bash
tar -czf - ./my_project | python3 foxpipe.py send 1.2.3.4 9000 -p secret
```

### Destination

```bash
python3 foxpipe.py receive 9000 -p secret | tar -xzf -
```

---

## 🔒 Security

* **Encryption:** AES-GCM (random 12-byte nonce per chunk)
* **Key Derivation:** Scrypt (random 16-byte salt)
* **Integrity:** Authenticated encryption (tamper detection)
* **Streaming:** 4KB chunks (constant memory usage)

---

## ⚠️ Security Notes

* Password must be shared securely between sender and receiver
* No identity verification (yet) — vulnerable to MITM in hostile networks
* Intended for **trusted or controlled environments**

---

## 🗺️ Roadmap

* 🔗 NAT traversal / hole punching
* 📦 Optional compression (`zlib`, `lz4`)
* 🔑 FoxKey (human-friendly session codes)
* ⚡ Rust core for high-performance transfers

---

## 🧠 Philosophy

FoxPipe follows the Unix philosophy:

> **Do one thing well.**

No dashboards. No accounts. No external services.
Just fast, secure, pipeable data transfer.

---

## 👥 Maintainers

**FoxHackerzDevs Team**

---

## ⚡ TL;DR

```bash
# Receiver
python3 foxpipe.py receive 8080 -p secret > file

# Sender
cat file | python3 foxpipe.py send <IP> 8080 -p secret
```

---

🦊 **Build. Break. Secure.**
