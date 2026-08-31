#!/usr/bin/env python3
"""
Comprehensive Test Suite for Micro-Redis-Vault
==============================================
Tests core networking, RESP protocol parser, thread-safe memory engine,
cryptographic envelope integrity, rate-limiting, and audit ledger.
"""

import unittest
import time
import os
import socket
import threading
import json
from micro_redis_vault import (
    CryptoEngine,
    AuditLedger,
    RateLimiter,
    StorageEngine,
    RespParser,
    MicroRedisVaultServer
)

class TestCryptoEngine(unittest.TestCase):
    def setUp(self):
        self.salt = b"0123456789abcdef"
        self.passphrase = "UltraSecurePassphrase2026!"
        self.key = CryptoEngine.derive_key(self.passphrase, self.salt)

    def test_key_derivation_deterministic(self):
        key2 = CryptoEngine.derive_key(self.passphrase, self.salt)
        self.assertEqual(self.key, key2)
        self.assertEqual(len(self.key), 32) # 256 bits

    def test_encrypt_decrypt_roundtrip(self):
        plaintext = b"Sensitive Session Token: sk_live_998877665544332211"
        envelope = CryptoEngine.encrypt(plaintext, self.key)
        self.assertNotEqual(plaintext, envelope)
        decrypted = CryptoEngine.decrypt(envelope, self.key)
        self.assertEqual(plaintext, decrypted)

    def test_tamper_detection(self):
        plaintext = b"Critical financial transfer data"
        envelope = bytearray(CryptoEngine.encrypt(plaintext, self.key))
        # Tamper with a single bit in the ciphertext
        envelope[20] ^= 0xFF
        with self.assertRaises(ValueError):
            CryptoEngine.decrypt(bytes(envelope), self.key)

    def test_invalid_key_fails(self):
        plaintext = b"Top secret payload"
        envelope = CryptoEngine.encrypt(plaintext, self.key)
        wrong_key = CryptoEngine.derive_key("WrongPassword123", self.salt)
        with self.assertRaises(ValueError):
            CryptoEngine.decrypt(envelope, wrong_key)


class TestAuditLedger(unittest.TestCase):
    def setUp(self):
        self.test_log = "test_audit.log"
        if os.path.exists(self.test_log):
            os.remove(self.test_log)
        self.ledger = AuditLedger(log_path=self.test_log)

    def tearDown(self):
        if os.path.exists(self.test_log):
            os.remove(self.test_log)

    def test_hash_chain_integrity(self):
        self.ledger.log("127.0.0.1", "SET user:1 Alice")
        self.ledger.log("127.0.0.1", "SET user:2 Bob")
        self.ledger.log("192.168.1.5", "AUTH.PASSPHRASE secret123")
        valid, count, msg = self.ledger.verify_integrity()
        self.assertTrue(valid)
        self.assertEqual(count, 3)

    def test_tamper_detection_on_disk(self):
        self.ledger.log("127.0.0.1", "SET user:1 Alice")
        self.ledger.log("127.0.0.1", "SET user:2 Bob")
        self.ledger.log("192.168.1.5", "AUTH.PASSPHRASE secret123")
        # Intentionally alter an entry on disk
        with open(self.test_log, "r") as f:
            lines = f.readlines()
        entry = json.loads(lines[1])
        entry["command"] = "SET user:2 MALICIOUS_PAYLOAD" # Modified command
        lines[1] = json.dumps(entry) + "\n"
        with open(self.test_log, "w") as f:
            f.writelines(lines)

        valid, count, msg = self.ledger.verify_integrity()
        self.assertFalse(valid)
        self.assertIn("Checksum mismatch", msg)


class TestRateLimiter(unittest.TestCase):
    def setUp(self):
        self.limiter = RateLimiter(max_failures=3, window_seconds=2, jail_seconds=5)

    def test_sliding_window_and_jailing(self):
        ip = "10.0.0.99"
        # 1st failure
        jailed, rem = self.limiter.record_failure(ip)
        self.assertFalse(jailed)
        self.assertEqual(rem, 2)
        # 2nd failure
        jailed, rem = self.limiter.record_failure(ip)
        self.assertFalse(jailed)
        # 3rd failure -> Jail triggered!
        jailed, jail_dur = self.limiter.record_failure(ip)
        self.assertTrue(jailed)
        self.assertEqual(jail_dur, 5)

        # Check is_jailed status
        is_j, rem_sec = self.limiter.is_jailed(ip)
        self.assertTrue(is_j)
        self.assertGreater(rem_sec, 0)

        # Other IP is unaffected
        is_j_other, _ = self.limiter.is_jailed("192.168.1.1")
        self.assertFalse(is_j_other)


class TestStorageEngineAndSearch(unittest.TestCase):
    def setUp(self):
        self.storage = StorageEngine(persist_file="test_dump.enc")
        self.storage.unlock_vault("MasterPassword2026")

    def tearDown(self):
        if os.path.exists("test_dump.enc"):
            os.remove("test_dump.enc")
        if os.path.exists("salt.bin"):
            os.remove("salt.bin")

    def test_basic_set_get_del(self):
        self.storage.set("name", "Alice")
        self.assertEqual(self.storage.get("name").value, "Alice")
        self.assertTrue(self.storage.exists("name"))
        self.assertTrue(self.storage.delete("name"))
        self.assertIsNone(self.storage.get("name"))

    def test_ttl_expiration(self):
        self.storage.set("temp_key", "temporary_data", ttl_sec=0.1)
        self.assertIsNotNone(self.storage.get("temp_key"))
        time.sleep(0.15)
        # Passive expiration on get
        self.assertIsNone(self.storage.get("temp_key"))

    def test_full_text_search_inverted_index(self):
        self.storage.set("doc1", "Redis in-memory caching and speed")
        self.storage.set("doc2", "Zero dependency cryptography vault in Python")
        self.storage.set("doc3", "Redis cryptography in memory")

        results = self.storage.search("cryptography")
        self.assertEqual(results, ["doc2", "doc3"])

        multi_results = self.storage.search("redis memory")
        self.assertEqual(multi_results, ["doc1", "doc3"])

    def test_encrypted_persistence_roundtrip(self):
        self.storage.set("secret_1", "EncryptedPassword99", is_encrypted=True)
        self.storage.set("public_1", "PublicProfileData", is_encrypted=False)

        ok, msg = self.storage.save_snapshot()
        self.assertTrue(ok)
        self.assertTrue(os.path.exists("test_dump.enc"))

        # Verify disk file is ciphertext (not plaintext JSON)
        with open("test_dump.enc", "rb") as f:
            disk_content = f.read()
        self.assertNotIn(b"EncryptedPassword99", disk_content)
        self.assertNotIn(b"PublicProfileData", disk_content)

        # Clear memory
        self.storage.flush()
        self.assertIsNone(self.storage.get("secret_1"))

        # Restore from encrypted disk
        ok_rest, msg_rest = self.storage.load_snapshot()
        self.assertTrue(ok_rest)
        self.assertEqual(self.storage.get("secret_1").value, "EncryptedPassword99")
        self.assertEqual(self.storage.get("public_1").value, "PublicProfileData")


class TestRespParser(unittest.TestCase):
    def test_simple_string_serialization(self):
        self.assertEqual(RespParser.serialize_simple_string("OK"), b"+OK\r\n")

    def test_bulk_string_serialization(self):
        self.assertEqual(RespParser.serialize_bulk_string("hello"), b"$5\r\nhello\r\n")
        self.assertEqual(RespParser.serialize_bulk_string(None), b"$-1\r\n")

    def test_resp_stream_parsing(self):
        raw = b"*3\r\n$3\r\nSET\r\n$4\r\nname\r\n$5\r\nAlice\r\n"
        args, rest = RespParser.parse_stream(raw)
        self.assertEqual(args, ["SET", "name", "Alice"])
        self.assertEqual(rest, b"")

    def test_inline_command_parsing(self):
        raw = b'SET "user session" "secret token value"\r\n'
        args, rest = RespParser.parse_stream(raw)
        self.assertEqual(args, ["SET", "user session", "secret token value"])


class TestWebServerStartup(unittest.TestCase):
    def test_web_server_port_conflict_does_not_crash(self):
        bound_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        bound_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        bound_sock.bind(("127.0.0.1", 0))
        port = bound_sock.getsockname()[1]
        bound_sock.listen(1)
        server = MicroRedisVaultServer(host="127.0.0.1", port=6379, web_port=port, enable_web=True)

        result = {}

        def run_server():
            try:
                server._start_web_server()
                result["raised"] = False
            except OSError as exc:
                result["raised"] = True
                result["error"] = str(exc)

        worker = threading.Thread(target=run_server, daemon=True)
        worker.start()
        worker.join(timeout=3)

        try:
            self.assertFalse(worker.is_alive(), "Web server startup should not block on a port conflict")
            self.assertFalse(result.get("raised", False), "Web server should handle a port conflict without raising")
        finally:
            bound_sock.close()


if __name__ == "__main__":
    unittest.main()
