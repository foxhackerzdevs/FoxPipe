## 🦊 FoxPipe

**Secure. Simple. Reliable. Data Streaming.**

FoxPipe is a minimalist CLI utility for end-to-end encrypted data transfer between two machines. It’s built on a simple idea: moving data should feel like using a Unix pipe—without compromising security.

---

## 🚀 Why FoxPipe?

* **Simple**
  No accounts, no cloud, no complex setup. Just a sender and a receiver.

* **Practical**
  Pipe anything—tarballs, database dumps, backups, or live logs.

* **Reliable**
  Uses AES-256-GCM authenticated encryption with Scrypt key derivation.

* **Clean**
  Progress and status logs go to `stderr`, keeping `stdout` pure for piping.

---

## 🛠️ Usage

### 1. Receiver (Destination Machine)

Start the listener and redirect output to a file:

```bash
python3 foxpipe.py receive 8080 -p "your-secure-password" > received_data.zip
```

---

### 2. Sender (Source Machine)

Pipe data directly into FoxPipe:

```bash
cat large_file.zip | python3 foxpipe.py send 192.168.1.5 8080 -p "your-secure-password"
```

---

## 📦 Advanced: Piping Folders

### Source

```bash
tar -czf - ./my_project | python3 foxpipe.py send 1.2.3.4 9000 -p secret
```

### Destination

```bash
python3 foxpipe.py receive 9000 -p secret | tar -xzf -
```

---

## 🔒 Security Specs

* **Encryption:** AES-GCM (12-byte random nonce per chunk)
* **KDF:** Scrypt (16-byte random salt, (2^{14}) cost factor)
* **Integrity:** Authenticated encryption prevents tampering
* **Performance:** Streams in 4KB chunks (low memory footprint)

---

## 🗺️ Roadmap

* NAT Hole Punching → direct P2P across firewalls
* Compression → optional `zlib` / `lz4` support
* FoxKey → human-readable mnemonic connection codes
* Rust Core → high-performance rewrite for multi-gigabit speeds

---

## 🧠 Philosophy

FoxPipe follows the Unix philosophy:

> *Do one thing well.*

No dashboards. No dependencies on external services.
Just secure, fast, pipeable data transfer.

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

🦊 *Build. Break. Secure.*
