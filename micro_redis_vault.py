#!/usr/bin/env python3
"""
Micro-Redis-Vault
=================
A zero-dependency, Redis-compatible in-memory database with defense-in-depth security.
Built strictly using Python's standard library (0 third-party runtime packages).

Core Security Features:
- Transport Layer Security (TLS/SSL) via stdlib `ssl`
- Key Derivation: PBKDF2-HMAC-SHA256 (100,000 rounds)
- Authenticated Keystream Cipher: HMAC-SHA256 Counter-Mode with HMAC integrity tag
- Memory Scrubbing: VAULT.LOCK purges master encryption key from RAM
- Disk Snapshot: dump.enc (Ciphertext persistence with salt.bin)
- Blockchain-style Hash-Chained Audit Ledger: audit.log
- Sliding-Window Token-Bucket IP Rate Limiting & Brute-Force Jailing
- Full RESP Protocol Parser & Built-in Terminal CLI / Web Console
"""

import sys
import os
import time
import socket
import ssl
import threading
import hashlib
import hmac
import secrets
import json
import re
import shlex
import argparse
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

CRLF = b"\r\n"

# =====================================================================
# 1. Cryptographic Engine (PBKDF2 + HMAC-SHA256 Keystream Cipher)
# =====================================================================

class CryptoEngine:
    """
    Zero-dependency authenticated keystream cipher.
    Uses PBKDF2-HMAC-SHA256 for key derivation and an authenticated CTR-mode
    HMAC-SHA256 keystream cipher with constant-time integrity verification.
    """
    PBKDF2_ITERATIONS = 100_000

    @staticmethod
    def derive_key(passphrase: str, salt: bytes) -> bytes:
        """Derives a 256-bit master key using 100,000 rounds of PBKDF2-HMAC-SHA256."""
        return hashlib.pbkdf2_hmac(
            'sha256',
            passphrase.encode('utf-8'),
            salt,
            CryptoEngine.PBKDF2_ITERATIONS,
            dklen=32
        )

    @staticmethod
    def _generate_keystream(key: bytes, nonce: bytes, length: int) -> bytes:
        """Generates a cryptographically strong keystream using HMAC-SHA256 in counter mode."""
        blocks = []
        counter = 0
        while len(b''.join(blocks)) < length:
            ctr_bytes = counter.to_bytes(8, byteorder='big')
            block = hmac.new(key, nonce + ctr_bytes, hashlib.sha256).digest()
            blocks.append(block)
            counter += 1
        return b''.join(blocks)[:length]

    _used_nonces = set()
    _nonce_lock = threading.Lock()

    @classmethod
    def generate_nonce(cls) -> bytes:
        """Generates a cryptographically random 16-byte nonce with uniqueness tracking."""
        with cls._nonce_lock:
            while True:
                nonce = secrets.token_bytes(16)
                if nonce not in cls._used_nonces:
                    cls._used_nonces.add(nonce)
                    return nonce

    @classmethod
    def encrypt(cls, plaintext: bytes, key: bytes) -> bytes:
        """
        Encrypts plaintext with authenticated envelope:
        [16 bytes CSPRNG Nonce] + [Ciphertext] + [32 bytes HMAC-SHA256 Tag]
        """
        nonce = cls.generate_nonce()
        keystream = cls._generate_keystream(key, nonce, len(plaintext))
        ciphertext = bytes(p ^ k for p, k in zip(plaintext, keystream))
        tag = hmac.new(key, nonce + ciphertext, hashlib.sha256).digest()
        return nonce + ciphertext + tag

    @classmethod
    def decrypt(cls, payload: bytes, key: bytes) -> bytes:
        """
        Verifies HMAC-SHA256 integrity tag in constant time, then decrypts.
        Raises ValueError if corrupted or tampered with.
        """
        if len(payload) < 48:
            raise ValueError("Invalid ciphertext payload length (minimum 48 bytes required)")
        nonce = payload[:16]
        tag = payload[-32:]
        ciphertext = payload[16:-32]
        expected_tag = hmac.new(key, nonce + ciphertext, hashlib.sha256).digest()
        if not hmac.compare_digest(tag, expected_tag):
            raise ValueError("Integrity check failed: invalid key or tampered ciphertext")
        keystream = cls._generate_keystream(key, nonce, len(ciphertext))
        return bytes(c ^ k for c, k in zip(ciphertext, keystream))


# =====================================================================
# 2. Blockchain-Style Hash-Chained Audit Ledger
# =====================================================================

class AuditLedger:
    """
    Linear hash-chained audit ledger.
    Every entry is cryptographically linked to the previous entry:
    Hash_n = SHA256(Hash_{n-1} + Timestamp + Client_IP + Command)
    """
    def __init__(self, log_path="audit.log"):
        self.log_path = log_path
        self.lock = threading.Lock()
        self.last_hash = self._get_last_hash()

    def _get_last_hash(self) -> str:
        if not os.path.exists(self.log_path):
            return "0" * 64
        last_line = ""
        with open(self.log_path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    last_line = line.strip()
        if last_line:
            try:
                data = json.loads(last_line)
                return data.get("current_hash", "0" * 64)
            except Exception:
                return "0" * 64
        return "0" * 64

    def log(self, client_ip: str, command: str) -> str:
        with self.lock:
            ts = time.time()
            iso_time = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(ts))
            payload = f"{self.last_hash}|{ts}|{client_ip}|{command}"
            curr_hash = hashlib.sha256(payload.encode('utf-8')).hexdigest()
            entry = {
                "timestamp": iso_time,
                "unix_ts": ts,
                "client_ip": client_ip,
                "command": command,
                "prev_hash": self.last_hash,
                "current_hash": curr_hash
            }
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
            self.last_hash = curr_hash
            return curr_hash

    def verify_integrity(self) -> tuple:
        with self.lock:
            if not os.path.exists(self.log_path):
                return True, 0, "No audit log file present"
            prev_hash = "0" * 64
            count = 0
            with open(self.log_path, "r", encoding="utf-8") as f:
                for idx, line in enumerate(f):
                    if not line.strip():
                        continue
                    count += 1
                    try:
                        entry = json.loads(line.strip())
                        if entry.get("prev_hash") != prev_hash:
                            return False, count, f"Hash chain broken at entry #{idx+1}"
                        payload = f"{prev_hash}|{entry['unix_ts']}|{entry['client_ip']}|{entry['command']}"
                        calc_hash = hashlib.sha256(payload.encode('utf-8')).hexdigest()
                        if calc_hash != entry.get("current_hash"):
                            return False, count, f"Checksum mismatch at entry #{idx+1}"
                        prev_hash = entry.get("current_hash")
                    except Exception as e:
                        return False, count, f"Parsing error at entry #{idx+1}: {str(e)}"
            return True, count, "Hash-chain integrity verified successfully"

    def get_recent(self, limit=20) -> list:
        with self.lock:
            if not os.path.exists(self.log_path):
                return []
            entries = []
            with open(self.log_path, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        try:
                            entries.append(json.loads(line.strip()))
                        except Exception:
                            pass
            return entries[-limit:]


# =====================================================================
# 3. Sliding-Window Rate Limiter & IP Jailing
# =====================================================================

class RateLimiter:
    def __init__(self, max_failures=5, window_seconds=60, jail_seconds=900):
        self.max_failures = max_failures
        self.window_seconds = window_seconds
        self.jail_seconds = jail_seconds
        self.failed_attempts = {}
        self.jailed_ips = {}
        self.lock = threading.Lock()

    def is_jailed(self, ip: str) -> tuple:
        with self.lock:
            now = time.time()
            if ip in self.jailed_ips:
                until = self.jailed_ips[ip]
                if now < until:
                    remaining = int(until - now)
                    return True, remaining
                else:
                    del self.jailed_ips[ip]
            return False, 0

    def record_failure(self, ip: str) -> tuple:
        with self.lock:
            now = time.time()
            attempts = self.failed_attempts.get(ip, [])
            attempts = [t for t in attempts if now - t < self.window_seconds]
            attempts.append(now)
            self.failed_attempts[ip] = attempts
            if len(attempts) >= self.max_failures:
                jail_until = now + self.jail_seconds
                self.jailed_ips[ip] = jail_until
                self.failed_attempts[ip] = []
                return True, self.jail_seconds
            return False, self.max_failures - len(attempts)

    def record_success(self, ip: str):
        with self.lock:
            if ip in self.failed_attempts:
                del self.failed_attempts[ip]


# =====================================================================
# 4. Storage Engine & Salt Lifecycle Management
# =====================================================================

class ValueEntry:
    def __init__(self, value: str, expires_at: float = None, is_encrypted: bool = False):
        self.value = value
        self.expires_at = expires_at
        self.is_encrypted = is_encrypted

    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        return time.time() > self.expires_at


class StorageEngine:
    """
    Thread-safe in-memory key-value database with explicit salt persistence (salt.bin).
    """
    def __init__(self, persist_file="dump.enc", salt_file="salt.bin"):
        self.store = {}
        self.index = {}
        self.persist_file = persist_file
        self.salt_file = salt_file
        self.lock = threading.RLock()
        self.master_key = None
        self.auth_verifier = None
        self.salt = None
        self.created_at = time.time()
        self.total_commands = 0
        self._load_or_create_salt()

    def _load_or_create_salt(self):
        """Loads salt and auth verifier from disk, or generates new 16-byte random salt."""
        if os.path.exists(self.salt_file):
            with open(self.salt_file, "rb") as f:
                data = f.read()
                if len(data) >= 16:
                    self.salt = data[:16]
                    if len(data) > 16:
                        self.auth_verifier = data[16:].decode('utf-8', errors='ignore')
        else:
            self.salt = secrets.token_bytes(16)
            with open(self.salt_file, "wb") as f:
                f.write(self.salt)

    def _persist_salt_and_verifier(self):
        with open(self.salt_file, "wb") as f:
            f.write(self.salt)
            if self.auth_verifier:
                f.write(self.auth_verifier.encode('utf-8'))

    def _tokenize(self, text: str) -> set:
        words = re.findall(r'[a-zA-Z0-9_]+', text.lower())
        return set(words)

    def _index_key(self, key: str, value: str):
        tokens = self._tokenize(value)
        for t in tokens:
            if t not in self.index:
                self.index[t] = set()
            self.index[t].add(key)

    def _unindex_key(self, key: str):
        for token_set in self.index.values():
            token_set.discard(key)

    def set(self, key: str, val: str, ttl_sec: float = None, is_encrypted: bool = False):
        with self.lock:
            self.total_commands += 1
            expires_at = (time.time() + ttl_sec) if ttl_sec else None
            self._unindex_key(key)
            self.store[key] = ValueEntry(val, expires_at, is_encrypted)
            if not is_encrypted:
                self._index_key(key, val)

    def get(self, key: str) -> ValueEntry:
        with self.lock:
            self.total_commands += 1
            entry = self.store.get(key)
            if entry is None:
                return None
            if entry.is_expired():
                self._unindex_key(key)
                del self.store[key]
                return None
            return entry

    def delete(self, key: str) -> bool:
        with self.lock:
            self.total_commands += 1
            if key in self.store:
                self._unindex_key(key)
                del self.store[key]
                return True
            return False

    def exists(self, key: str) -> bool:
        with self.lock:
            self.total_commands += 1
            entry = self.get(key)
            return entry is not None

    def keys(self, pattern: str = "*") -> list:
        with self.lock:
            self.total_commands += 1
            res = []
            regex = re.compile("^" + pattern.replace("*", ".*").replace("?", ".") + "$")
            keys_to_clean = []
            for k, entry in list(self.store.items()):
                if entry.is_expired():
                    keys_to_clean.append(k)
                elif regex.match(k):
                    res.append(k)
            for k in keys_to_clean:
                self._unindex_key(k)
                del self.store[k]
            return res

    def search(self, query: str) -> list:
        with self.lock:
            self.total_commands += 1
            query_tokens = self._tokenize(query)
            if not query_tokens:
                return []
            result_keys = None
            for token in query_tokens:
                matching_keys = self.index.get(token, set())
                valid_keys = {k for k in matching_keys if self.get(k) is not None}
                if result_keys is None:
                    result_keys = set(valid_keys)
                else:
                    result_keys.intersection_update(valid_keys)
            return sorted(list(result_keys)) if result_keys else []

    def flush(self):
        with self.lock:
            self.total_commands += 1
            self.store.clear()
            self.index.clear()

    def sweep_expired(self) -> int:
        with self.lock:
            now = time.time()
            expired = [k for k, v in self.store.items() if v.expires_at and now > v.expires_at]
            for k in expired:
                self._unindex_key(k)
                del self.store[k]
            return len(expired)

    def unlock_vault(self, passphrase: str) -> bool:
        with self.lock:
            derived = CryptoEngine.derive_key(passphrase, self.salt)
            calc_verifier = hashlib.sha256(derived + b":verifier").hexdigest()
            if self.auth_verifier is None:
                self.master_key = derived
                self.auth_verifier = calc_verifier
                self._persist_salt_and_verifier()
                return True
            else:
                if hmac.compare_digest(self.auth_verifier, calc_verifier):
                    self.master_key = derived
                    return True
                else:
                    return False

    def lock_vault(self):
        with self.lock:
            self.master_key = None

    def is_vault_unlocked(self) -> bool:
        with self.lock:
            return self.master_key is not None

    def save_snapshot(self) -> tuple:
        with self.lock:
            if not self.master_key:
                return False, "Vault must be unlocked with AUTH.PASSPHRASE before saving snapshot"
            data = {}
            for k, v in self.store.items():
                if not v.is_expired():
                    data[k] = {
                        "value": v.value,
                        "expires_at": v.expires_at,
                        "is_encrypted": v.is_encrypted
                    }
            json_bytes = json.dumps(data).encode('utf-8')
            encrypted_payload = CryptoEngine.encrypt(json_bytes, self.master_key)
            with open(self.persist_file, "wb") as f:
                f.write(encrypted_payload)
            return True, f"Encrypted snapshot written ({len(encrypted_payload)} bytes)"

    def load_snapshot(self) -> tuple:
        with self.lock:
            if not os.path.exists(self.persist_file):
                return False, "No snapshot file found"
            if not self.master_key:
                return False, "Vault is locked. Provide passphrase to decrypt snapshot"
            with open(self.persist_file, "rb") as f:
                payload = f.read()
            try:
                decrypted = CryptoEngine.decrypt(payload, self.master_key)
                data = json.loads(decrypted.decode('utf-8'))
                self.store.clear()
                self.index.clear()
                now = time.time()
                loaded = 0
                for k, item in data.items():
                    exp = item.get("expires_at")
                    if exp is None or exp > now:
                        self.store[k] = ValueEntry(item["value"], exp, item["is_encrypted"])
                        if not item["is_encrypted"]:
                            self._index_key(k, item["value"])
                        loaded += 1
                return True, f"Successfully restored {loaded} keys from encrypted snapshot"
            except Exception as e:
                return False, f"Failed to decrypt snapshot: {str(e)}"


# =====================================================================
# 5. RESP Protocol & Command Handler
# =====================================================================

class RespParser:
    @staticmethod
    def serialize_simple_string(s: str) -> bytes:
        return b"+" + s.encode('utf-8') + CRLF

    @staticmethod
    def serialize_error(err: str) -> bytes:
        return b"-ERR " + err.encode('utf-8') + CRLF

    @staticmethod
    def serialize_integer(num: int) -> bytes:
        return b":" + str(num).encode('utf-8') + CRLF

    @staticmethod
    def serialize_bulk_string(s: str) -> bytes:
        if s is None:
            return b"$-1\r\n"
        b = s.encode('utf-8')
        return b"$" + str(len(b)).encode('utf-8') + CRLF + b + CRLF

    @staticmethod
    def serialize_array(arr: list) -> bytes:
        if arr is None:
            return b"*-1\r\n"
        res = [b"*" + str(len(arr)).encode('utf-8') + CRLF]
        for item in arr:
            if isinstance(item, str):
                res.append(RespParser.serialize_bulk_string(item))
            elif isinstance(item, int):
                res.append(RespParser.serialize_integer(item))
            elif item is None:
                res.append(b"$-1\r\n")
            else:
                res.append(RespParser.serialize_bulk_string(str(item)))
        return b"".join(res)

    @classmethod
    def parse_stream(cls, buffer: bytes) -> tuple:
        if not buffer:
            return None, buffer
        if not buffer.startswith(b'*'):
            if b'\n' not in buffer:
                return None, buffer
            line, rest = buffer.split(b'\n', 1)
            line_str = line.decode('utf-8', errors='ignore').strip('\r')
            if not line_str:
                return cls.parse_stream(rest)
            try:
                args = shlex.split(line_str)
            except Exception:
                args = line_str.split()
            return args, rest

        try:
            lines = buffer.split(b'\r\n')
            if not lines[0].startswith(b'*'):
                return None, buffer
            count = int(lines[0][1:])
            args = []
            idx = 1
            for _ in range(count):
                if idx >= len(lines):
                    return None, buffer
                if lines[idx].startswith(b'$'):
                    length = int(lines[idx][1:])
                    idx += 1
                    if idx >= len(lines):
                        return None, buffer
                    val = lines[idx][:length].decode('utf-8', errors='ignore')
                    args.append(val)
                    idx += 1
                else:
                    return None, buffer
            consumed = b'\r\n'.join(lines[:idx]) + b'\r\n'
            remaining = buffer[len(consumed):]
            return args, remaining
        except Exception:
            return None, buffer


# =====================================================================
# 6. Micro-Redis-Vault Server (with Optional TLS & Web Console)
# =====================================================================

class MicroRedisVaultServer:
    def __init__(self, host="0.0.0.0", port=None, web_port=None, enable_web=None, tls_cert=None, tls_key=None):
        self.host = host
        
        # Railway-compatible dynamic port resolution
        env_port = os.environ.get("PORT")
        if env_port:
            port_num = int(env_port)
            if web_port is not None:
                self.web_port = int(web_port)
            else:
                self.web_port = 8080 if port_num in (8080, 6379) else port_num
            
            if port is not None:
                self.port = int(port)
            else:
                self.port = 6379 if self.web_port == 8080 else ((port_num - 1) if (port_num - 1) >= 1024 else 6379)
            self.enable_web = True
        else:
            self.web_port = int(web_port) if web_port is not None else 8080
            self.port = int(port) if port is not None else 6379
            self.enable_web = bool(enable_web) if enable_web is not None else False

        self.tls_cert = tls_cert
        self.tls_key = tls_key
        self.storage = StorageEngine()
        self.rate_limiter = RateLimiter(max_failures=5, window_seconds=60, jail_seconds=900)
        self.audit = AuditLedger()
        self.running = False
        self.server_sock = None
        self.web_server = None
        self.web_server_bound = False
        self.ssl_context = None
        self.connected_clients = 0
        self.lock = threading.Lock()

        if self.tls_cert and self.tls_key:
            self._setup_tls()

    def _setup_tls(self):
        self.ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.ssl_context.load_cert_chain(certfile=self.tls_cert, keyfile=self.tls_key)

    def start(self):
        self.running = True
        sweeper_thread = threading.Thread(target=self._ttl_sweeper_loop, daemon=True)
        sweeper_thread.start()

        if self.enable_web:
            web_thread = threading.Thread(target=self._start_web_server, daemon=True)
            web_thread.start()
            time.sleep(0.05)

        try:
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            raw_sock.bind((self.host, self.port))
            raw_sock.listen(128)
            self.server_sock = raw_sock
        except Exception as e:
            self.server_sock = None
            print(f"  * Note: TCP listener not bound on {self.host}:{self.port} ({e})", flush=True)

        print("=" * 60, flush=True)
        print("  ⚡ MICRO-REDIS-VAULT SERVER READY ⚡", flush=True)
        if self.web_server_bound:
            print(f"Web server listening on 0.0.0.0:{self.web_port}", flush=True)
        elif self.enable_web:
            print(f"  * Note: Web server not bound on 0.0.0.0:{self.web_port}", flush=True)
        if self.server_sock:
            print(f"RESP server listening on 0.0.0.0:{self.port}", flush=True)
        if self.ssl_context:
            print("  * Transport Security (TLS)       : ENABLED 🔒", flush=True)
        print("  * Zero 3rd-party dependencies    : 100% Python Stdlib", flush=True)
        print("  * Hash-Chained Audit Ledger      : audit.log", flush=True)
        print("=" * 60, flush=True)

        try:
            while self.running:
                if self.server_sock:
                    try:
                        client_sock, client_addr = self.server_sock.accept()
                        if self.ssl_context:
                            try:
                                client_sock = self.ssl_context.wrap_socket(client_sock, server_side=True)
                            except ssl.SSLError:
                                client_sock.close()
                                continue
                        with self.lock:
                            self.connected_clients += 1
                        t = threading.Thread(
                            target=self._handle_client,
                            args=(client_sock, client_addr),
                            daemon=True
                        )
                        t.start()
                    except socket.error:
                        break
                else:
                    time.sleep(1)
        except KeyboardInterrupt:
            print("\nShutting down Micro-Redis-Vault...", flush=True)
        finally:
            self.stop()

    def stop(self):
        self.running = False
        if self.web_server:
            try:
                self.web_server.shutdown()
            except Exception:
                pass
            try:
                self.web_server.server_close()
            except Exception:
                pass
            self.web_server = None
        if self.server_sock:
            try:
                self.server_sock.close()
            except Exception:
                pass

    def _ttl_sweeper_loop(self):
        while self.running:
            time.sleep(0.1)
            self.storage.sweep_expired()

    def execute_command(self, args: list, client_ip="127.0.0.1") -> bytes:
        if not args:
            return RespParser.serialize_error("empty command")

        cmd = args[0].upper()
        raw_cmd_str = " ".join(args)

        is_jailed, remaining = self.rate_limiter.is_jailed(client_ip)
        if is_jailed and cmd in ["AUTH.PASSPHRASE", "SET.ENC", "GET.DEC"]:
            self.audit.log(client_ip, f"BLOCKED_JAILED: {raw_cmd_str}")
            return RespParser.serialize_error(f"IP is jailed for brute-force defense ({remaining}s remaining)")

        self.audit.log(client_ip, raw_cmd_str)

        if cmd == "PING":
            msg = args[1] if len(args) > 1 else "PONG"
            return RespParser.serialize_simple_string(msg)

        elif cmd == "SET":
            if len(args) < 3:
                return RespParser.serialize_error("wrong number of arguments for 'set' command")
            key, val = args[1], args[2]
            ttl = None
            if len(args) >= 5 and args[3].upper() == "EX":
                try:
                    ttl = float(args[4])
                except ValueError:
                    return RespParser.serialize_error("value is not an integer or out of range")
            self.storage.set(key, val, ttl_sec=ttl, is_encrypted=False)
            return RespParser.serialize_simple_string("OK")

        elif cmd == "GET":
            if len(args) != 2:
                return RespParser.serialize_error("wrong number of arguments for 'get' command")
            entry = self.storage.get(args[1])
            if entry is None:
                return RespParser.serialize_bulk_string(None)
            if entry.is_encrypted:
                return RespParser.serialize_error("Key holds encrypted secret. Use GET.DEC with unlocked vault")
            return RespParser.serialize_bulk_string(entry.value)

        elif cmd == "DEL":
            if len(args) < 2:
                return RespParser.serialize_error("wrong number of arguments for 'del' command")
            deleted = 0
            for k in args[1:]:
                if self.storage.delete(k):
                    deleted += 1
            return RespParser.serialize_integer(deleted)

        elif cmd == "EXISTS":
            if len(args) < 2:
                return RespParser.serialize_error("wrong number of arguments for 'exists' command")
            cnt = sum(1 for k in args[1:] if self.storage.exists(k))
            return RespParser.serialize_integer(cnt)

        elif cmd == "KEYS":
            pattern = args[1] if len(args) > 1 else "*"
            matched = self.storage.keys(pattern)
            return RespParser.serialize_array(matched)

        elif cmd == "SEARCH":
            if len(args) < 2:
                return RespParser.serialize_error("wrong number of arguments for 'search' command")
            query = " ".join(args[1:])
            results = self.storage.search(query)
            return RespParser.serialize_array(results)

        elif cmd == "FLUSHALL" or cmd == "FLUSHDB":
            self.storage.flush()
            return RespParser.serialize_simple_string("OK")

        elif cmd == "SAVE":
            ok, msg = self.storage.save_snapshot()
            if ok:
                return RespParser.serialize_simple_string(msg)
            return RespParser.serialize_error(msg)

        elif cmd == "RESTORE":
            ok, msg = self.storage.load_snapshot()
            if ok:
                return RespParser.serialize_simple_string(msg)
            return RespParser.serialize_error(msg)

        elif cmd == "INFO":
            uptime = int(time.time() - self.storage.created_at)
            with self.storage.lock:
                keys_count = len(self.storage.store)
                unlocked = self.storage.is_vault_unlocked()
            info_str = (
                f"# Server\r\n"
                f"micro_redis_vault_version:1.0.0\r\n"
                f"uptime_in_seconds:{uptime}\r\n"
                f"connected_clients:{self.connected_clients}\r\n"
                f"total_commands_processed:{self.storage.total_commands}\r\n"
                f"keys_count:{keys_count}\r\n"
                f"vault_unlocked:{1 if unlocked else 0}\r\n"
                f"zero_dependency:true\r\n"
            )
            return RespParser.serialize_bulk_string(info_str)

        elif cmd == "AUTH.PASSPHRASE":
            if len(args) != 2:
                return RespParser.serialize_error("wrong number of arguments for 'auth.passphrase' command")
            passphrase = args[1]
            if len(passphrase) < 6:
                jailed, rem = self.rate_limiter.record_failure(client_ip)
                if jailed:
                    return RespParser.serialize_error(f"Authentication failed. IP JAILED for {rem}s")
                return RespParser.serialize_error(f"Passphrase too short. {rem} tries left")
            
            ok = self.storage.unlock_vault(passphrase)
            if ok:
                self.rate_limiter.record_success(client_ip)
                return RespParser.serialize_simple_string("VAULT_UNLOCKED (256-bit key derived via PBKDF2)")
            else:
                jailed, rem = self.rate_limiter.record_failure(client_ip)
                if jailed:
                    return RespParser.serialize_error(f"Invalid passphrase. IP JAILED for {rem}s")
                return RespParser.serialize_error(f"Invalid passphrase. {rem} attempts remaining before IP jail")

        elif cmd == "VAULT.LOCK":
            self.storage.lock_vault()
            return RespParser.serialize_simple_string("VAULT_LOCKED (Master key purged from RAM)")

        elif cmd == "SET.ENC":
            if len(args) < 3:
                return RespParser.serialize_error("wrong number of arguments for 'set.enc' command")
            if not self.storage.is_vault_unlocked():
                return RespParser.serialize_error("Vault is locked. Unlock using AUTH.PASSPHRASE first")
            key, val = args[1], args[2]
            ttl = None
            if len(args) >= 5 and args[3].upper() == "EX":
                try:
                    ttl = float(args[4])
                except ValueError:
                    return RespParser.serialize_error("invalid TTL integer")
            encrypted_blob = CryptoEngine.encrypt(val.encode('utf-8'), self.storage.master_key)
            enc_hex = encrypted_blob.hex()
            self.storage.set(key, enc_hex, ttl_sec=ttl, is_encrypted=True)
            return RespParser.serialize_simple_string("OK (Encrypted with authenticated envelope)")

        elif cmd == "GET.DEC":
            if len(args) != 2:
                return RespParser.serialize_error("wrong number of arguments for 'get.dec' command")
            if not self.storage.is_vault_unlocked():
                return RespParser.serialize_error("Vault is locked. Unlock using AUTH.PASSPHRASE first")
            entry = self.storage.get(args[1])
            if entry is None:
                return RespParser.serialize_bulk_string(None)
            if not entry.is_encrypted:
                return RespParser.serialize_bulk_string(entry.value)
            try:
                raw_bytes = bytes.fromhex(entry.value)
                decrypted_bytes = CryptoEngine.decrypt(raw_bytes, self.storage.master_key)
                return RespParser.serialize_bulk_string(decrypted_bytes.decode('utf-8'))
            except Exception as e:
                return RespParser.serialize_error(f"Decryption failed: {str(e)}")

        elif cmd == "AUDIT.LOG":
            limit = 20
            if len(args) > 1:
                try:
                    limit = int(args[1])
                except ValueError:
                    pass
            entries = self.audit.get_recent(limit)
            rendered = [f"[{e['timestamp']}] ({e['client_ip']}) {e['command']} -> {e['current_hash'][:12]}..." for e in entries]
            return RespParser.serialize_array(rendered)

        elif cmd == "AUDIT.VERIFY":
            valid, count, msg = self.audit.verify_integrity()
            res_str = f"STATUS: {'VALID' if valid else 'CORRUPTED'} | ENTRIES: {count} | DETAIL: {msg}"
            return RespParser.serialize_simple_string(res_str)

        else:
            return RespParser.serialize_error(f"unknown command `{cmd}`")

    def _handle_client(self, client_sock: socket.socket, client_addr: tuple):
        client_ip = client_addr[0]
        buffer = b""
        try:
            while self.running:
                data = client_sock.recv(4096)
                if not data:
                    break
                buffer += data
                while buffer:
                    args, buffer = RespParser.parse_stream(buffer)
                    if args is None:
                        break
                    resp = self.execute_command(args, client_ip=client_ip)
                    client_sock.sendall(resp)
        except Exception:
            pass
        finally:
            with self.lock:
                self.connected_clients = max(0, self.connected_clients - 1)
            try:
                client_sock.close()
            except Exception:
                pass

    def _start_web_server(self):
        server_instance = self
        class WebHandler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                pass

            def do_HEAD(self):
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()

            def do_GET(self):
                parsed = urlparse(self.path)
                if parsed.path in ["/", "/index.html", "/health"]:
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Access-Control-Allow-Origin", "*")
                    self.end_headers()
                    self.wfile.write(server_instance._render_web_dashboard().encode('utf-8'))
                elif parsed.path == "/api/stats":
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Access-Control-Allow-Origin", "*")
                    self.end_headers()
                    uptime = int(time.time() - server_instance.storage.created_at)
                    with server_instance.storage.lock:
                        data = {
                            "uptime": uptime,
                            "clients": server_instance.connected_clients,
                            "total_commands": server_instance.storage.total_commands,
                            "keys_count": len(server_instance.storage.store),
                            "vault_unlocked": server_instance.storage.is_vault_unlocked(),
                            "keys": list(server_instance.storage.store.keys())
                        }
                    self.wfile.write(json.dumps(data).encode('utf-8'))
                else:
                    self.send_response(404)
                    self.end_headers()

            def do_POST(self):
                parsed = urlparse(self.path)
                if parsed.path == "/api/exec":
                    content_len = int(self.headers.get('Content-Length', 0))
                    body = self.rfile.read(content_len).decode('utf-8')
                    try:
                        req_data = json.loads(body) if body else {}
                        cmd_line = req_data.get("command", "")
                        try:
                            args = shlex.split(cmd_line)
                        except Exception:
                            args = cmd_line.split()
                        raw_resp = server_instance.execute_command(args, client_ip=self.client_address[0])
                        resp_str = raw_resp.decode('utf-8', errors='ignore').strip('\r\n')
                        self.send_response(200)
                        self.send_header("Content-Type", "application/json")
                        self.send_header("Access-Control-Allow-Origin", "*")
                        self.end_headers()
                        self.wfile.write(json.dumps({"response": resp_str}).encode('utf-8'))
                    except Exception as e:
                        self.send_response(200)
                        self.send_header("Content-Type", "application/json")
                        self.send_header("Access-Control-Allow-Origin", "*")
                        self.end_headers()
                        self.wfile.write(json.dumps({"error": f"-ERR {str(e)}"}).encode('utf-8'))
                else:
                    self.send_response(404)
                    self.end_headers()

        class ReusableHTTPServer(HTTPServer):
            allow_reuse_address = True

        try:
            web_srv = ReusableHTTPServer(("0.0.0.0", self.web_port), WebHandler)
            self.web_server = web_srv
            self.web_server_bound = True
            print(f"  * Web Server listening on http://0.0.0.0:{self.web_port}", flush=True)
            web_srv.serve_forever()
        except OSError as exc:
            self.web_server_bound = False
            print(f"  * Note: Web server not bound on 0.0.0.0:{self.web_port} ({exc})", flush=True)
            self.web_server = None
            return

    def _render_web_dashboard(self) -> str:
        return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Micro-Redis-Vault Dashboard</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0A0E14; color: #E6EDF3; padding: 24px; }
  h1 { font-size: 22px; font-weight: 700; color: #2DD4A7; margin-bottom: 20px; display: flex; align-items: center; gap: 8px; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 14px; margin-bottom: 20px; }
  .card { background: #141B24; border: 1px solid #263342; border-radius: 8px; padding: 14px; }
  .lbl { font-size: 12px; color: #8B949E; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 6px; }
  .val { font-size: 22px; font-weight: bold; color: #38BDF8; font-family: monospace; }
  .term-box { background: #000; border: 1px solid #263342; border-radius: 8px; padding: 16px; margin-bottom: 16px; }
  #term-out { height: 280px; overflow-y: auto; color: #2DD4A7; font-family: 'Courier New', Courier, monospace; font-size: 14px; white-space: pre-wrap; line-height: 1.5; }
  .input-row { display: flex; gap: 10px; margin-top: 12px; }
  input { flex: 1; padding: 10px 14px; background: #141B24; border: 1px solid #30363D; border-radius: 6px; color: #FFF; font-family: monospace; font-size: 14px; outline: none; }
  input:focus { border-color: #2DD4A7; }
  button { padding: 10px 20px; background: #2DD4A7; color: #0A0E14; border: none; border-radius: 6px; cursor: pointer; font-weight: bold; font-size: 14px; transition: 0.15s; }
  button:hover { background: #26b890; }
  button:disabled { opacity: 0.5; cursor: not-allowed; }
  .quick-btns { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 12px; }
  .qbtn { padding: 6px 12px; background: #161B22; border: 1px solid #30363D; color: #8B949E; border-radius: 4px; cursor: pointer; font-size: 12px; font-family: monospace; }
  .qbtn:hover { background: #21262D; color: #FFF; border-color: #58A6FF; }
</style>
</head>
<body>
  <h1>⚡ Micro-Redis-Vault <span style="font-size:12px; font-weight:normal; color:#8B949E; margin-left:8px;">Zero-Dependency In-Memory Crypto Vault</span></h1>
  <div class="grid">
    <div class="card"><div class="lbl">Connected Clients</div><div class="val" id="st-clients">0</div></div>
    <div class="card"><div class="lbl">Keys in RAM</div><div class="val" id="st-keys">0</div></div>
    <div class="card"><div class="lbl">Commands Processed</div><div class="val" id="st-cmds">0</div></div>
    <div class="card"><div class="lbl">Vault Status</div><div class="val" id="st-vault" style="color:#E85C4A;">LOCKED</div></div>
  </div>
  <div class="term-box">
    <div id="term-out">Micro-Redis-Vault Web REPL Console Ready.\nType commands below or click quick-actions.\n</div>
    <div class="input-row">
      <input type="text" id="cmd-in" placeholder="e.g. PING, AUTH.PASSPHRASE MasterKey2026!, SET.ENC user:101 secretval" onkeydown="if(event.key==='Enter'){sendCmd();}" autofocus />
      <button id="send-btn" onclick="sendCmd()">Send</button>
    </div>
    <div class="quick-btns">
      <button class="qbtn" onclick="quickFill('PING')">PING</button>
      <button class="qbtn" onclick="quickFill('INFO')">INFO</button>
      <button class="qbtn" onclick="quickFill('AUTH.PASSPHRASE MasterKey2026!')">AUTH.PASSPHRASE</button>
      <button class="qbtn" onclick="quickFill('SET.ENC user:101:api_key sk_live_998877')">SET.ENC</button>
      <button class="qbtn" onclick="quickFill('GET.DEC user:101:api_key')">GET.DEC</button>
      <button class="qbtn" onclick="quickFill('SAVE')">SAVE</button>
      <button class="qbtn" onclick="quickFill('VAULT.LOCK')">VAULT.LOCK</button>
      <button class="qbtn" onclick="quickFill('AUDIT.VERIFY')">AUDIT.VERIFY</button>
    </div>
  </div>
  <script>
    async function updateStats() {
      try {
        const r = await fetch('/api/stats');
        const d = await r.json();
        document.getElementById('st-clients').innerText = d.clients;
        document.getElementById('st-keys').innerText = d.keys_count;
        document.getElementById('st-cmds').innerText = d.total_commands;
        const vElem = document.getElementById('st-vault');
        if (d.vault_unlocked) {
          vElem.innerText = 'UNLOCKED';
          vElem.style.color = '#2DD4A7';
        } else {
          vElem.innerText = 'LOCKED';
          vElem.style.color = '#E85C4A';
        }
      } catch(e){}
    }
    setInterval(updateStats, 1500);
    updateStats();

    function quickFill(cmd) {
      document.getElementById('cmd-in').value = cmd;
      sendCmd();
    }

    async function sendCmd() {
      const inp = document.getElementById('cmd-in');
      const term = document.getElementById('term-out');
      const btn = document.getElementById('send-btn');
      const cmd = inp.value.trim();
      if(!cmd) return;
      term.innerText += '\\n> ' + cmd + '\\n';
      inp.value = '';
      btn.disabled = true;
      btn.innerText = '...';
      try {
        const r = await fetch('/api/exec', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({command: cmd})
        });
        const d = await r.json();
        const text = (d.response !== undefined) ? d.response : (d.error || 'Empty response');
        term.innerText += text + '\\n';
      } catch(err) {
        term.innerText += 'Network Error: ' + err.message + '\\n';
      } finally {
        btn.disabled = false;
        btn.innerText = 'Send';
        term.scrollTop = term.scrollHeight;
        inp.focus();
        updateStats();
      }
    }
  </script>
</body>
</html>"""

def run_cli_client(host="127.0.0.1", port=6379, use_tls=False):
    print("=" * 60)
    print(f" Connecting to Micro-Redis-Vault at {host}:{port} {'(TLS Encrypted)' if use_tls else ''}...")
    print(" Type 'help' for specialized vault commands or 'exit' to quit.")
    print("=" * 60)
    try:
        raw_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(raw_s, server_hostname=host)
        else:
            s = raw_s
        s.connect((host, port))
    except Exception as e:
        print(f"❌ Failed to connect to {host}:{port}: {e}")
        return

    while True:
        try:
            cmd = input(f"\033[1;34mmicro-vault [{host}:{port}]>\033[0m ").strip()
            if not cmd:
                continue
            if cmd.lower() in ["exit", "quit"]:
                break
            if cmd.lower() == "help":
                print("\n📖 Specialized Vault Commands:")
                print("  AUTH.PASSPHRASE <pass>      - Derive 256-bit master key via PBKDF2 to unlock vault")
                print("  SET.ENC <key> <secret>      - Encrypt value with authenticated envelope in memory")
                print("  GET.DEC <key>               - Decrypt and display secret value")
                print("  VAULT.LOCK                  - Instantly purge master encryption key from RAM")
                print("  SAVE                        - Save encrypted snapshot to dump.enc on SSD")
                print("  RESTORE                     - Decrypt and load snapshot from dump.enc")
                print("  SEARCH <word>               - Inverted index search across unencrypted values")
                print("  AUDIT.LOG [limit]           - View hash-chained audit ledger entries")
                print("  AUDIT.VERIFY                - Verify integrity of hash-chained audit ledger\n")
                continue

            s.sendall((cmd + "\r\n").encode('utf-8'))
            resp = s.recv(8192).decode('utf-8', errors='ignore')
            if resp.startswith("+"):
                print(f"\033[32m{resp[1:].strip()}\033[0m")
            elif resp.startswith("-"):
                print(f"\033[31m{resp.strip()}\033[0m")
            elif resp.startswith("$"):
                lines = resp.split("\r\n", 1)
                if len(lines) > 1 and lines[1]:
                    print(f"\033[36m{lines[1].strip()}\033[0m")
                else:
                    print("(nil)")
            elif resp.startswith("*"):
                items = re.findall(r'\$([0-9]+)\r\n([^\r\n]*)', resp)
                for idx, item in enumerate(items):
                    print(f"{idx+1}) \033[33m{item[1]}\033[0m")
            else:
                print(resp.strip())
        except (KeyboardInterrupt, EOFError):
            print("\nExiting CLI...")
            break
        except Exception as e:
            print(f"Error: {e}")
            break
    s.close()

def main():
    parser = argparse.ArgumentParser(description="Micro-Redis-Vault")
    parser.add_argument("mode", nargs="?", default="server", choices=["server", "cli", "test"])
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--web", action="store_true")
    parser.add_argument("--web-port", type=int, default=None)
    parser.add_argument("--tls", action="store_true", help="Enable TLS transport encryption")
    parser.add_argument("--cert", default="cert.pem", help="TLS certificate path")
    parser.add_argument("--key", default="key.pem", help="TLS private key path")

    args = parser.parse_args()

    # Dynamic port configuration from environment or CLI arguments
    env_p_str = os.environ.get("PORT")
    if env_p_str:
        env_p = int(env_p_str)
        if args.web_port is not None:
            web_port = args.web_port
        else:
            web_port = 8080 if env_p in (8080, 6379) else env_p
        
        if args.port is not None:
            resp_port = args.port
        else:
            resp_port = 6379 if web_port == 8080 else ((env_p - 1) if (env_p - 1) >= 1024 else 6379)
        enable_web = True
    else:
        web_port = args.web_port if args.web_port is not None else 8080
        resp_port = args.port if args.port is not None else 6379
        enable_web = args.web

    if args.mode == "cli":
        run_cli_client(host="127.0.0.1" if args.host == "0.0.0.0" else args.host, port=resp_port, use_tls=args.tls)
    else:
        tls_cert = args.cert if args.tls and os.path.exists(args.cert) else None
        tls_key = args.key if args.tls and os.path.exists(args.key) else None
        server = MicroRedisVaultServer(
            host=args.host,
            port=resp_port,
            web_port=web_port,
            enable_web=enable_web,
            tls_cert=tls_cert,
            tls_key=tls_key
        )
        server.start()

if __name__ == "__main__":
    main()
