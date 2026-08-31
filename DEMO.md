# 🎥 Micro-Redis-Vault Demo & Deployment

[![Watch the Demo](https://img.shields.io/badge/YouTube-Watch%20Demo%20Video-red?style=for-the-badge&logo=youtube)](https://youtube.com)

> **Live Web Console URL:** [https://perceptive-wisdom-production-c752.up.railway.app/](https://perceptive-wisdom-production-c752.up.railway.app/)  
> **Live Public TCP Proxy:** `turntable.proxy.rlwy.net:58674`  
> **Connect via CLI:** `python3 micro_redis_vault.py cli --host turntable.proxy.rlwy.net --port 58674`  
> **Connect via Netcat:** `nc turntable.proxy.rlwy.net 58674`  
> **Hackathon Tracks:** Track D (Data & Storage) & Track E (Security & Crypto)

---

## ⚡ Live Cloud Verification:
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

## 🎬 5-Minute Video Breakdown:
* **0:00 - 0:30** • Zero-Dependency Proof (`requirements.txt` is 0 bytes)
* **0:30 - 0:45** • The Hook: 2013 Target / BlackPOS RAM Scraper Vulnerability
* **0:45 - 1:30** • Single-Command Launch & 11 Replaced Packages
* **1:30 - 2:30** • Live Vault Demo (`SET.ENC`, `GET.DEC`, `SAVE`, and `VAULT.LOCK` memory scrubbing)
* **2:30 - 3:30** • Automated Brute-Force Attack & Live IP Jailing
* **3:30 - 4:15** • Blockchain-Style Hash-Chained Audit Ledger & Tamper Detection
* **4:15 - 5:00** • Conclusion & Standard Library Craft
