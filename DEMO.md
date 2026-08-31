# 🎥 Micro-Redis-Vault Demo & Presentation Guide

[![Watch the Demo](https://img.shields.io/badge/YouTube-Watch%20Demo%20Video-red?style=for-the-badge&logo=youtube)](https://youtube.com)

> **Live Web Console URL:** [https://perceptive-wisdom-production-c752.up.railway.app/](https://perceptive-wisdom-production-c752.up.railway.app/)  
> **Live Public TCP Proxy:** `turntable.proxy.rlwy.net:58674`  
> **Connect via CLI:** `python3 micro_redis_vault.py cli --host turntable.proxy.rlwy.net --port 58674`  
> **Connect via Netcat:** `nc turntable.proxy.rlwy.net 58674`  
> **Hackathon Tracks:** Track D (Data & Storage) & Track E (Security & Crypto)

---

## ⚡ Live Cloud Verification

Anyone or any judge can connect to our live deployed instance over public TCP:

```bash
# Connect with standard Netcat over the internet:
nc turntable.proxy.rlwy.net 58674

# Send Redis commands:
PING
+PONG

AUTH.PASSPHRASE MySecret2026!
+VAULT_UNLOCKED (256-bit key derived via PBKDF2)

SET.ENC user:101:token "sk_live_998877"
+OK (Encrypted with authenticated envelope)

GET.DEC user:101:token
$14
sk_live_998877
```

---

## 🎬 5-Minute Video Agenda & Speaking Script

### ⏱️ Timestamp Breakdown
* **[0:00 - 0:45]** The Hook: 2013 Target / BlackPOS RAM Scraper Vulnerability
* **[0:45 - 1:30]** Why Zero Dependencies Matters & Single-Command Launch
* **[1:30 - 2:30]** Live Vault Demo (`SET.ENC`, `GET.DEC`, `SAVE`, and `VAULT.LOCK` memory zeroing)
* **[2:30 - 3:30]** Automated Brute-Force Attack Simulation & Live IP Jailing
* **[3:30 - 4:15]** Tamper-Evident Hash-Chained Audit Ledger (`AUDIT.VERIFY`)
* **[4:15 - 5:00]** Conclusion & The Power of Standard Library Craft

---

### 🎙️ Word-for-Word Pitch Presentation Script

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

