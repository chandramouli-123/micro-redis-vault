# Micro-Redis-Vault — Definitive Architecture

## Mermaid Diagram (paste into any Mermaid renderer or IcePanel)

```mermaid
flowchart TD

    classDef client fill:#1E293B,stroke:#38BDF8,stroke-width:2px,color:#F8FAFC,font-weight:bold
    classDef net    fill:#0F172A,stroke:#64748B,stroke-width:2px,color:#F8FAFC
    classDef shield fill:#1E1B4B,stroke:#818CF8,stroke-width:2px,color:#F8FAFC
    classDef crypto fill:#064E3B,stroke:#34D399,stroke-width:3px,color:#F8FAFC,font-weight:bold
    classDef store  fill:#1C1917,stroke:#F59E0B,stroke-width:2px,color:#F8FAFC
    classDef disk   fill:#450A0A,stroke:#F87171,stroke-width:2px,color:#F8FAFC
    classDef gate   fill:#1E1B4B,stroke:#34D399,stroke-width:2px,color:#F8FAFC,font-style:italic

    CLI["Developer CLI REPL
    python3 micro_redis_vault.py cli
    AUTH.PASSPHRASE - SET.ENC - GET.DEC
    VAULT.LOCK - AUDIT.LOG - SAVE"]:::client

    WEB["Web Browser Console
    http://127.0.0.1:6380
    Live dashboard - Browser REPL
    Stats - Info - REST /cmd"]:::client

    ATK["Attacker / Legacy Client
    redis-cli - netcat - socket
    PING - SET - GET
    Automated credential spray"]:::client

    CLI & WEB & ATK -->|TCP Stream| TLSGATE

    TLSGATE(["ssl.SSLContext
    TLS Handshake Gate
    Optional client cert wrap"]):::gate

    TLSGATE --> NET

    subgraph NET ["LAYER 1 - NETWORK AND PROTOCOL | socket - ssl - threading - shlex"]
        direction LR
        TCP["TCP Listener
        socket.AF_INET
        0.0.0.0:6379
        SO_REUSEADDR listen(128)"]:::net

        POOL["Thread-Per-Client Pool
        threading.Thread daemon=True
        One thread per connection"]:::net

        RESP["RESP Frame Decoder
        shlex tokenizer
        Inline + Array frames
        Outputs clean token list"]:::net

        HTTP["HTTP Web Server
        http.server.HTTPServer
        Port 6380 - GET + POST
        Dashboard and REST API"]:::net

        TCP -->|"accept()"| POOL
        POOL -->|"recv(4096)"| RESP
        POOL -.->|"web traffic"| HTTP
    end

    RESP -->|"Clean command tokens"| SHIELD

    subgraph SHIELD ["LAYER 2 - DEFENSE AND COMPLIANCE | time - json - hashlib.sha256 - threading.Lock"]
        direction LR
        RL["Sliding-Window Rate Limiter
        Token-bucket per source IP
        window=60s - max_fails=5
        threading.Lock protected"]:::shield

        JAIL["Brute-Force IP Jailer
        jailed_until = now + 900s
        Socket severed immediately
        All subsequent reqs dropped"]:::shield

        LEDGER["Hash-Chained Audit Ledger
        H_n = SHA256 of H_n-1 + ts + IP + cmd
        Append-only to audit.log
        AUDIT.VERIFY detects tampering"]:::shield

        RL -->|"5th failure triggers"| JAIL
        RL -.->|"every command logged"| LEDGER
    end

    JAIL -. "DROP - ERR IP JAILED 900s" .-> ATK

    SHIELD -->|"Authenticated rate-checked ops"| VAULT

    subgraph VAULT ["LAYER 3 - CRYPTOGRAPHIC VAULT ENGINE | hashlib.pbkdf2_hmac - secrets - hmac"]
        direction LR
        KDF["PBKDF2-HMAC-SHA256
        Key Derivation - 100000 rounds
        Outputs 256-bit master key
        salt.bin persisted on disk"]:::crypto

        NONCE["CSPRNG Nonce Generator
        secrets.token_bytes(16)
        Fresh 16B nonce per write
        Keystream never reused"]:::crypto

        STREAM["Counter-Mode Keystream
        HMAC-SHA256-CTR
        key + nonce + counter block
        XOR applied over plaintext"]:::crypto

        TAG["Authenticated Envelope
        16B Nonce + Ciphertext + 32B HMAC Tag
        hmac.compare_digest constant-time
        Encrypt-then-MAC pattern"]:::crypto

        LOCK["VAULT.LOCK
        master_key = None
        RAM pointer scrubbed instantly
        Defeats BlackPOS-style scrapers"]:::crypto

        KDF --> NONCE --> STREAM --> TAG
        TAG -.->|"VAULT.LOCK wipes key"| LOCK
    end

    VAULT -->|"Ciphertext envelopes [Nonce|Cipher|Tag]"| STORAGE

    subgraph STORAGE ["LAYER 4 - IN-MEMORY STORE AND PERSISTENCE | threading.RLock - dict - set - re"]
        direction LR
        RAM["Mutex-Protected KV Store
        threading.RLock
        O(1) SET GET DEL EXISTS
        ValueEntry: value + ttl + flag"]:::store

        TTL["Active TTL Sweeper
        100ms daemon thread loop
        sweep_expired() every tick
        Passive check on GET"]:::store

        SEARCH["Inverted Index Engine
        Tokenized set intersections
        SEARCH multi-keyword
        re.findall tokenizer"]:::store

        SNAP["Snapshot Manager
        SAVE writes dump.enc
        RESTORE loads dump.enc
        salt.bin lifecycle managed"]:::store

        RAM <-->|"sweep expired"| TTL
        RAM <-->|"index on SET"| SEARCH
        RAM -->|"SAVE"| SNAP
        SNAP -->|"RESTORE"| RAM
    end

    SNAP -->|"Binary file I/O"| DISK

    subgraph DISK ["DISK PERSISTENCE"]
        direction LR
        DUMPENC["dump.enc
        JSON-serialised ciphertext
        Authenticated envelope only
        Zero plaintext on SSD"]:::disk

        SALTBIN["salt.bin
        16-byte CSPRNG salt
        Deterministic key re-derive
        on restart with passphrase"]:::disk
    end

    DISK -->|"Loaded at RESTORE"| RAM
    RAM -->|"RESP sendall() back to client"| POOL
    HTTP -->|"HTTP 200 JSON"| WEB
```

---

## Python Class Map

| Layer | Stdlib Modules | Python Class |
|:---|:---|:---|
| Network & Protocol | `socket`, `ssl`, `threading`, `shlex`, `http.server` | `MicroRedisVaultServer`, `RespParser` |
| Defense & Compliance | `time`, `json`, `hashlib`, `threading.Lock` | `RateLimiter`, `AuditLedger` |
| Cryptographic Vault | `hashlib.pbkdf2_hmac`, `secrets`, `hmac` | `CryptoEngine` |
| In-Memory Storage | `threading.RLock`, `dict`, `set`, `re` | `StorageEngine`, `ValueEntry` |

## Full Command Reference

| Command | Routed Through | Description |
|:---|:---|:---|
| `AUTH.PASSPHRASE <pass>` | Shield → Vault | Derives 256-bit key via PBKDF2 (100k rounds) |
| `SET.ENC <key> <val>` | Vault → Store | Encrypts with HMAC authenticated envelope in RAM |
| `GET.DEC <key>` | Store → Vault | Decrypts and returns plaintext value |
| `VAULT.LOCK` | Vault | Scrubs master key pointer from RAM |
| `SET / GET / DEL / EXISTS / KEYS` | Store | Standard Redis-compatible plaintext ops |
| `TTL / EXPIRE` | Store | Key expiry swept every 100ms |
| `SEARCH <word>` | Store | Inverted index full-text search |
| `SAVE` | Store → Disk | Writes authenticated ciphertext to dump.enc |
| `RESTORE` | Disk → Store | Loads and decrypts snapshot from dump.enc |
| `AUDIT.LOG [n]` | Shield | Returns last N hash-chained ledger entries |
| `AUDIT.VERIFY` | Shield | Verifies SHA-256 chain — catches any tamper |
| `FLUSHALL / FLUSHDB` | Store | Wipe all keys from in-memory store |
| `INFO` | Server | Runtime stats, version, key count, uptime |
| `PING` | Network | Liveness probe — returns +PONG |
