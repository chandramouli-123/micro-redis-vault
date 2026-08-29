# 🏛️ Micro-Redis-Vault: Complete Architecture, System Design & Pitch Guide

> **Event:** Zero Dependency | 72-Hour Hackathon 2026 (Hackathon Raptors)  
> **Target Award:** Grand Prize (₹80,000) • Package Killer Award (₹10,000) • Best Write-Up (₹30,000)  
> **Core Constraint:** 100% Python Standard Library Primitives (0 Third-Party Runtime Dependencies).

---

## 📑 Table of Contents
1. [The Real-World Problem & The "BlackPOS" Hook](#1-the-real-world-problem--the-blackpos-hook)
2. [End-to-End System Architecture](#2-end-to-end-system-architecture)
3. [The 4 Core Architectural Layers](#3-the-4-core-architectural-layers)
4. [Step-by-Step Data Flow & Execution Sequences](#4-step-by-step-data-flow--execution-sequences)
5. [Technical Glossary (First-Principles Precision)](#5-technical-glossary-first-principles-precision)
6. [Zero-Dependency Manifest & Package Killer Table](#6-zero-dependency-manifest--package-killer-table)
7. [Judge-Calibrated 5-Minute Pitch Script](#7-judge-calibrated-5-minute-pitch-script)

---

## 1. The Real-World Problem & The "BlackPOS" Hook

### The Story:
In 2013, retail giant **Target** suffered a breach where **40 million credit card numbers** were stolen. Attackers didn't break complex disk encryption—they installed a memory scraper called **BlackPOS** inside RAM. The moment a customer swiped their card, the plaintext numbers were scraped directly from memory before they ever touched a hard drive.

### The Modern Cloud Dilemma:
Today, every tech company uses **Redis** as a microsecond in-memory layer holding their most critical secrets:
* Live User Session Tokens & OAuth Access Keys
* Production API Keys & Database Connection Strings
* Customer PII (Personally Identifiable Information)

### Why Standard Redis Fails in High-Security Environments:
1. **Unprotected Memory:** Redis stores raw strings in cleartext RAM. Anyone with container or root access running a core dump (`gcore redis-server`) can extract all active session tokens in seconds.
2. **Unencrypted Disk Backups:** Redis snapshots (`dump.rdb`) written to SSD or S3 backups are unencrypted plaintext.
3. **No Native Brute-Force Jailing:** Standard Redis allows infinite password guesses per second without rate-limiting.

### 🌟 The Solution: Micro-Redis-Vault
A Redis-compatible in-memory database with defense-in-depth security where **every stored key-value pair is treated as a cryptographically protected secret**—built with **ZERO third-party runtime dependencies**.

---

## 2. End-to-End System Architecture

```
                                ┌──────────────────────────────────────────────┐
                                │     Clients (CLI / Web Browser / Netcat)     │
                                └──────────────────────┬───────────────────────┘
                                                       │
                                 RESP / TCP Stream (Port 6379 / TLS Optional)
                                                       │
 ┌─────────────────────────────────────────────────────▼─────────────────────────────────────────────────────┐
 │ 1. NETWORK & CONCURRENCY LAYER                                                                            │
 │    • Low-level Sockets (socket.AF_INET, socket.SOCK_STREAM) + Optional TLS (ssl.SSLContext)              │
 │    • Multi-threaded Worker Pool (threading.Thread per client connection)                                │
 │    • Binary-Safe RESP Protocol & Shlex Command Tokenizer                                                  │
 └─────────────────────────────────────────────────────┬─────────────────────────────────────────────────────┘
                                                       │ Clean Command Arguments
                                                       ▼
 ┌───────────────────────────────────────────────────────────────────────────────────────────────────────────┐
 │ 2. DEFENSE & SECURITY SHIELD                                                                              │
 │    • Sliding-Window Token-Bucket Rate Limiter (Tracks failed attempts in memory dict)                     │
 │    • Brute-Force Defense Jailer (Auto-quarantines offending IP for 15 minutes after 5 failed attempts)   │
 │    • Blockchain-Style Linear Hash-Chained Audit Ledger (audit.log)                                        │
 └─────────────────────────────────────────────────────┬─────────────────────────────────────────────────────┘
                                                       │ Authenticated & Rate-Checked Traffic
                                                       ▼
 ┌───────────────────────────────────────────────────────────────────────────────────────────────────────────┐
 │ 3. CRYPTOGRAPHIC VAULT ENGINE                                                                             │
 │    • PBKDF2 Key Derivation (Passphrase + 16B Salt + 100,000 rounds -> 256-bit Master Key)                 │
 │    • Authenticated Keystream Cipher: [16B Nonce] + [Ciphertext] + [32B HMAC-SHA256 Integrity Seal]      │
 │    • Dynamic Memory Zeroing (VAULT.LOCK purges master key reference from RAM)                             │
 └─────────────────────────────────────────────────────┬─────────────────────────────────────────────────────┘
                                                       │
                         ┌─────────────────────────────┴─────────────────────────────┐
                         │                                                           │
 ┌───────────────────────▼───────────────────────────┐       ┌───────────────────────▼───────────────────────┐
 │ 4A. IN-MEMORY DATA STORE & SEARCH                 │       │ 4B. ENCRYPTED PERSISTENCE (DISK)              │
 │     • Thread-safe Mutex-Protected Dictionary      │       │     • Ciphertext Snapshot (dump.enc)          │
 │     • Passive & Active 100ms TTL Sweeper Thread   │       │     • Persisted Salt Lifecycle (salt.bin)     │
 │     • Inverted Full-Text Index Search Engine      │       │     • Zero plaintext ever touches SSD         │
 └───────────────────────────────────────────────────┘       └───────────────────────────────────────────────┘
```

---

## 3. The 4 Core Architectural Layers

| Layer | Responsibility | Standard Library Modules Used |
| :--- | :--- | :--- |
| **Layer 1: Network & Concurrency** | Listens on port 6379, manages concurrent connections, optional TLS encryption, and serializes/deserializes RESP commands. | `socket`, `ssl`, `threading`, `shlex`, `http.server` |
| **Layer 2: Defense Shield** | Protects against credential-stuffing attacks and maintains an immutable hash-chained audit trail. | `time`, `json`, `hashlib.sha256`, `threading.Lock` |
| **Layer 3: Cryptographic Vault** | Derives keys via 100k PBKDF2 rounds, encrypts/decrypts secrets via counter-mode HMAC keystream, and prevents memory scraping via key scrubbing. | `hashlib.pbkdf2_hmac`, `secrets`, `hmac` |
| **Layer 4: Storage & Persistence** | In-memory key-value storage, TTL expiration, full-text search, and encrypted SSD snapshots with persisted salt. | `re`, `collections`, standard `dict` & `set` |

---

## 4. Step-by-Step Data Flow & Execution Sequences

### 🔄 Flow A: How `SET.ENC` Encrypts and Saves a Secret
1. Client sends: `SET.ENC user:101:api_key "sk_live_998877"`
2. Server verifies that the vault is unlocked (`master_key is not None`).
3. Crypto engine generates a fresh 16-byte CSPRNG `nonce`.
4. Plaintext `"sk_live_998877"` is scrambled into ciphertext using a counter-mode HMAC-SHA256 keystream.
5. HMAC-SHA256 calculates a 32-byte tamper-proof integrity tag over `nonce + ciphertext`.
6. Resulting envelope (`nonce + ciphertext + tag`) is hex-encoded and saved to RAM dictionary.
7. Hash-chained audit ledger records the action into `audit.log`.
8. Server returns: `+OK (Encrypted with authenticated envelope)
`.

### 🔓 Flow B: How `GET.DEC` Decrypts a Secret
1. Client sends: `GET.DEC user:101:api_key`
2. Server reads the hex envelope from RAM dictionary.
3. Server splits envelope into `nonce (16B)`, `ciphertext`, and `tag (32B)`.
4. Server computes expected HMAC-SHA256 seal using `master_key`.
5. If tags match: Decrypts ciphertext and returns `$21
sk_live_998877
`.
6. If tags do not match: Returns `-ERR Integrity check failed: tampered ciphertext
`.

### 🛡️ Flow C: How `VAULT.LOCK` Defeats Memory Scrapers
1. Admin sends: `VAULT.LOCK`
2. Server executes `self.master_key = None`.
3. The cryptographic key is immediately purged from Python's RAM.
4. All stored secrets remain in ciphertext form in RAM.
5. If a memory scraper dumps the process RAM, it only finds uncrackable ciphertext.

### 🚨 Flow D: How Sliding-Window Rate Limiting Jails Attackers
1. Attacker sends 5 consecutive incorrect passphrases within 60 seconds.
2. Rate limiter records timestamps: `[T1, T2, T3, T4, T5]`.
3. Threshold of 5 failures is reached: Rate limiter sets `jailed_until = time.time() + 900` (15 mins).
4. Sockets immediately drop connections from this IP with `-ERR IP JAILED for 900s`.

---

## 5. Technical Glossary (First-Principles Precision)

* **Salt (`salt.bin`):** A random 16-byte string mixed into the passphrase and persisted across restarts. Ensures two identical passphrases produce completely different encryption keys, rendering Rainbow Table precomputed attacks useless.
* **PBKDF2-HMAC-SHA256:** A key stretching function that hashes passphrase + salt 100,000 times in a loop. It takes 20 milliseconds on CPU, but makes GPU dictionary attacks mathematically infeasible.
* **Nonce:** A "Number used ONCE". A unique 16-byte random number generated for every write so encrypting the same text twice produces two completely different ciphertexts.
* **HMAC-SHA256:** A Hash-based Message Authentication Code used as an unforgeable cryptographic seal to verify data integrity and prevent bit-flipping attacks.
* **Hash-Chained Ledger:** A linear cryptographic chain where entry $N$ contains $	ext{SHA256}(H_{N-1} + 	ext{Data})$, ensuring historical modifications are immediately caught.
* **RESP:** Redis Serialization Protocol. A prefix-length binary protocol using `+` (String), `-` (Error), `:` (Integer), `$` (Bulk String), and `*` (Array).
* **Mutex Lock (`threading.Lock`):** An operating system primitive ensuring thread-safety over shared memory during concurrent read/write operations.

---

## 6. Zero-Dependency Manifest & Package Killer Table

| # | Industry Package Replaced | Python Standard Library Replacement | Downloads / Impact |
| :-: | :--- | :--- | :--- |
| **1** | `redis` / `ioredis` | `socket` + `threading` (Raw TCP & RESP) | Billions of downloads |
| **2** | `node-vault` / `hvac` | `hashlib` + `secrets` (Key Management) | Ubiquitous Vault Clients |
| **3** | `bcrypt` / `argon2-cffi` | `hashlib.pbkdf2_hmac` (100k Key Stretching) | Top Password Hashing Libs |
| **4** | `crypto-js` / `pycryptodome` | `hmac` + `secrets` + `hashlib` (Keystream Cipher) | Top Cryptographic Toolkits |
| **5** | `express-rate-limit` | `time` + standard `dict` (Sliding Window) | Standard Web Rate Limiter |
| **6** | `winston` / `pino` / `log4j` | `json` + `hashlib.sha256` (Chained Ledger) | Ubiquitous Loggers |
| **7** | `tls` / `https` / `pyOpenSSL` | `ssl` (`ssl.SSLContext` Socket Wrapping) | Transport Layer Security |
| **8** | `express` / `fastify` | `http.server` + `urllib.parse` (Web Console) | Standard Web Frameworks |
| **9** | `lunr` / `flexsearch` | `re` + `set` + `dict` (Inverted Index) | Full-Text Search Engines |
| **10** | `redis-benchmark` | `socket` + `statistics` (Load Tester) | Standard Benchmark Tool |
| **11** | `node-cron` / `apscheduler` | `threading.Thread` (Background Sweeper) | Task Schedulers |

---

## 7. Judge-Calibrated 5-Minute Pitch Script

### ⏱️ Timestamped Presentation Guide:

```
[0:00 - 0:45] The Hook (The Target/BlackPOS In-Memory Vulnerability)
[0:45 - 1:30] Why Zero Dependencies Matters & Single-Command Launch
[1:30 - 2:30] Live Vault Demo (SET.ENC, GET.DEC, Ciphertext on Disk, Memory Zeroing)
[2:30 - 3:30] Live Attack Simulation & Instant IP Jailing
[3:30 - 4:15] Tamper-Proof Hash-Chained Audit Trail
[4:15 - 5:00] Closing & The Power of Standard Library Craft
```

### 🎙️ Word-for-Word Speaking Script:

#### **[0:00 - 0:45] The Hook**
> *"In 2013, Target lost 40 million credit card numbers — not because their firewall failed, but because malware called BlackPOS reached directly into server memory and copied card numbers the instant they were swiped, before they ever touched a disk. That's the blind spot most systems still have today: data sitting in RAM, completely unprotected, even when everything on disk is locked down.*
> 
> *Every modern app uses Redis the same exposed way — session tokens, API keys, personal data, all sitting in plain memory. If someone dumps that memory, or steals a backup file, it's all readable, instantly.*
> 
> *We built **Micro-Redis-Vault**: a Redis-compatible database that treats every single value as a secret — encrypted in memory, encrypted on disk, and built with zero third-party code. Every line is pure Python standard library."*

#### **[0:45 - 1:30] Why Zero Dependencies Matters**
> *"Most software today runs on hundreds of packages you didn't write and probably haven't audited — that's how supply-chain attacks happen. We asked: how much of a production-grade, encrypted database can we build using nothing but what ships inside Python itself?*
> 
> *The answer: all of it. No installs, no external libraries, one command to launch the whole system — server, web console, and vault together."*

#### **[1:30 - 2:30] Live Vault Demo**
> *"Let's watch it work. First, we unlock the vault with a passphrase. Behind the scenes, that passphrase is run through 100,000 rounds of key stretching — a deliberately slow process that takes a fraction of a second for us, but would take an attacker years to brute-force.*
> 
> *Now we store a secret — an API key. Before it ever touches memory, it's wrapped: a unique random value ensures no two secrets ever look alike even if the content repeats, and a cryptographic seal is attached so any tampering is instantly detectable.*
> 
> *Watch what's on disk right now — this is our saved snapshot. It's not gibberish that could be decoded; it's real ciphertext, unreadable without the master key.*
> 
> *And here's the key trick: if we lock the vault, the master key itself is wiped from memory. Any malware trying to scrape RAM at this point — like BlackPOS did — finds nothing but encrypted noise."*

#### **[2:30 - 3:30] Live Attack Simulation**
> *"Now let's see what happens when someone tries to break in. I'm running an automated password-guessing script against the vault right now.*
> 
> *Watch — attempt one, two, three, four, rejected... and on the fifth wrong guess, the system locks that attacker's connection out entirely for fifteen minutes. No brute-forcing your way past this."*

#### **[3:30 - 4:15] Tamper-Proof Audit Trail**
> *"Every action taken on this vault — every unlock, every read, every write — is logged, and each log entry is cryptographically linked to the one before it, like a chain.*
> 
> *If anyone tries to quietly edit or delete a line in that log after the fact — even changing a single character — running our verify command catches it immediately and points to exactly where the chain broke."*

#### **[4:15 - 5:00] Closing**
> *"In our write-up, we document eleven industry-standard packages we replaced entirely with Python's built-in tools — from Redis clients to encryption libraries to rate limiters — all without adding a single dependency.*
> 
> *Micro-Redis-Vault proves you don't need a hundred packages to build something secure. Sometimes the safest code is the code you didn't have to import. Thank you."*
