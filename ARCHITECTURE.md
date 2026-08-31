# Micro-Redis-Vault — Definitive Architecture & Technical Specification

> A zero-dependency, Redis-compatible in-memory database with defense-in-depth cryptographic security, dynamic memory scrubbing, and automated IP jailing.

![Architecture Diagram](./arch.png)

---

## 🏛️ System Architecture Layers

Micro-Redis-Vault organizes its responsibilities into four strictly isolated architectural layers across Python standard library primitives:

```
╔══════════════════════╦══════════════════════╦═══════════════════════════════════╦════════════════════════╗
║  🖥️  CLIENTS         ║  📡  NETWORK         ║  🛡️  DEFENSE & 🔑 CRYPTO VAULT   ║  💾  STORAGE & DISK    ║
╠══════════════════════╬══════════════════════╬═══════════════════════════════════╬════════════════════════╣
║  • Developer CLI     ║  • Raw TCP (6379)    ║  • Sliding-Window Rate Limiter    ║  • Mutex Store (RLock) ║
║  • Web Console       ║  • TLS Context (ssl) ║  • Automated IP Jailer (15 min)  ║  • 100ms TTL Sweeper   ║
║  • Redis-CLI / NC    ║  • Thread Pool       ║  • PBKDF2-HMAC Key Derivation     ║  • Inverted Search Idx ║
║  • Automated Spray   ║  • RESP Parser       ║  • HMAC-SHA256 Keystream Cipher   ║  • dump.enc Snapshot   ║
║                      ║  • HTTP Server(8080) ║  • Linear Hash-Chained Audit Log  ║  • salt.bin (16B salt) ║
╚══════════════════════╩══════════════════════╩═══════════════════════════════════╩════════════════════════╝
```

### Python Class Map

| Layer | Stdlib Modules | Python Class | Purpose |
|:---|:---|:---|:---|
| **Layer 1: Network & Protocol** | `socket`, `ssl`, `threading`, `shlex`, `http.server` | `MicroRedisVaultServer`, `RespParser` | Low-level TCP listener, multi-threaded worker pool, RESP parser, and Web dashboard HTTP server. |
| **Layer 2: Defense & Shield** | `time`, `json`, `hashlib`, `threading.Lock` | `RateLimiter`, `AuditLedger` | Sliding-window brute-force rate limiter, automated 15-min IP jailer, and linear hash-chained audit ledger. |
| **Layer 3: Cryptographic Vault** | `hashlib.pbkdf2_hmac`, `secrets`, `hmac` | `CryptoEngine` | 100,000-round PBKDF2 key derivation, counter-mode HMAC keystream cipher, and dynamic memory scrubbing. |
| **Layer 4: In-Memory Storage** | `threading.RLock`, `dict`, `set`, `re` | `StorageEngine`, `ValueEntry` | Thread-safe mutex store, active/passive 100ms TTL sweeper, inverted full-text search index, and encrypted snapshots. |

---

## 🔄 Step-by-Step Data Flow & Execution Sequences

### 🔐 Flow A: How `SET.ENC` Encrypts and Stores a Secret
1. Client sends: `SET.ENC user:101:api_key "sk_live_998877"`
2. Server verifies the vault is unlocked (`master_key is not None`).
3. Crypto engine generates a fresh 16-byte CSPRNG `nonce` via `secrets.token_bytes(16)`.
4. Plaintext `"sk_live_998877"` is scrambled into ciphertext using a counter-mode HMAC-SHA256 keystream.
5. HMAC-SHA256 calculates a 32-byte tamper-proof integrity tag over `nonce + ciphertext`.
6. Resulting envelope (`nonce + ciphertext + tag`) is hex-encoded and saved to the in-memory dictionary.
7. Hash-chained audit ledger appends the action to `audit.log`.
8. Server returns: `+OK (Encrypted with authenticated envelope)`.

### 🔓 Flow B: How `GET.DEC` Decrypts a Secret
1. Client sends: `GET.DEC user:101:api_key`
2. Server reads hex envelope from the in-memory dictionary.
3. Server splits envelope into `nonce (16B)`, `ciphertext`, and `tag (32B)`.
4. Server computes expected HMAC-SHA256 seal using `master_key`.
5. Constant-time comparison `hmac.compare_digest` verifies the tag.
6. If tags match: Decrypts ciphertext and returns `$14\r\nsk_live_998877\r\n`.
7. If tags mismatch: Returns `-ERR Decryption failed: tampered ciphertext`.

### 🛡️ Flow C: How `VAULT.LOCK` Defeats RAM Scraping (BlackPOS Vector)
1. Admin sends: `VAULT.LOCK`
2. Server executes `self.master_key = None`.
3. Master cryptographic key reference is immediately purged from RAM.
4. All stored secrets remain in encrypted ciphertext form in RAM.
5. If an attacker attaches a memory scraper (`gcore`) to process RAM, only encrypted ciphertext is extracted.

### 🚨 Flow D: How Sliding-Window Rate Limiting Jails Attackers
1. Attacker sends 5 consecutive invalid passphrases within 60 seconds.
2. Rate limiter records failure timestamps: `[T1, T2, T3, T4, T5]`.
3. Threshold of 5 failures is reached: Rate limiter sets `jailed_until = time.time() + 900` (15 mins).
4. Subsequent requests from this source IP are severed immediately with `-ERR IP is jailed for brute-force defense`.

---

## 📑 Technical Glossary (First-Principles Precision)

* **Salt (`salt.bin`):** A random 16-byte string mixed into the passphrase and persisted across restarts. Ensures two identical passphrases produce distinct encryption keys, rendering precomputed Rainbow Table attacks useless.
* **PBKDF2-HMAC-SHA256:** Key stretching function hashing passphrase + salt 100,000 times. Takes ~21 ms on CPU, making GPU dictionary brute-forcing mathematically infeasible.
* **Nonce:** "Number used ONCE". A unique 16-byte random number generated per write so encrypting the same text twice produces distinct ciphertexts.
* **HMAC-SHA256:** Hash-based Message Authentication Code used as an unforgeable cryptographic seal to verify integrity and prevent chosen-ciphertext attacks.
* **Hash-Chained Ledger:** A linear cryptographic chain where entry $N$ contains $H_N = \text{SHA256}(H_{N-1} + \text{Timestamp} + \text{IP} + \text{Cmd})$, ensuring historical log modifications break checksum integrity.
* **RESP:** Redis Serialization Protocol. Prefix-length binary protocol using `+` (Simple String), `-` (Error), `:` (Integer), `$` (Bulk String), and `*` (Array).
* **Mutex Lock (`threading.RLock`):** Operating system primitive ensuring thread-safety over shared memory during concurrent read/write operations.

---

## 🛡️ Threat Model & Security Boundaries

### ✅ Defended Threat Vectors:
1. **Memory-Scraping Malware (At Rest in RAM):** When `VAULT.LOCK` is issued, master key references are purged from RAM. In-memory data remains ciphertext, defeating RAM scrapers (like BlackPOS) and core dumps (`gcore`).
2. **Disk Snapshot Theft:** All snapshots (`dump.enc`) written to SSD/S3 backups are encrypted ciphertext with HMAC integrity seals.
3. **Automated Credential Stuffing:** Sliding-window rate limiter automatically quarantines offending IPs for 15 minutes after 5 failed authentication attempts.
4. **Audit Log Alteration:** Linear SHA-256 hash chaining ensures historical entry deletion or tampering breaks chain checksums flagged by `AUDIT.VERIFY`.
5. **Network Wire-Tapping:** Native TLS/SSL socket wrapping via stdlib `ssl` prevents wire-sniffing over TCP.

### ⚠️ Out-of-Scope Boundaries:
1. **Live Kernel / Root Debuggers:** Attackers with root privileges attaching `gdb` or `ptrace` at the exact microsecond `GET.DEC` decrypts a secret in active thread registers.
2. **Backdoored Python Binary:** Compromised host operating system Python runtime.
3. **Physical Cold-Boot Attacks:** Physical RAM freezing while the vault is in an active unlocked state.

---

## 📋 Full Command Reference

| Command | Routed Through | Description |
|:---|:---|:---|
| `AUTH.PASSPHRASE <pass>` | Shield → Vault | Derives 256-bit key via PBKDF2 (100k rounds) |
| `SET.ENC <key> <val>` | Vault → Store | Encrypts with HMAC authenticated envelope in RAM |
| `GET.DEC <key>` | Store → Vault | Decrypts and returns plaintext value |
| `VAULT.LOCK` | Vault | Scrubs master key pointer from RAM |
| `SET / GET / DEL / EXISTS / KEYS` | Store | Standard Redis-compatible plaintext ops |
| `TTL / EXPIRE` | Store | Key expiry swept every 100ms |
| `SEARCH <word>` | Store | Inverted index full-text search |
| `SAVE` | Store → Disk | Writes authenticated ciphertext snapshot to `dump.enc` |
| `RESTORE` | Disk → Store | Loads and decrypts snapshot from `dump.enc` |
| `AUDIT.LOG [n]` | Shield | Returns last N hash-chained ledger entries |
| `AUDIT.VERIFY` | Shield | Verifies SHA-256 chain — catches any log tampering |
| `FLUSHALL / FLUSHDB` | Store | Wipe all keys from in-memory store |
| `INFO` | Server | Runtime stats, version, key count, uptime |
| `PING` | Network | Liveness probe — returns `+PONG` |

