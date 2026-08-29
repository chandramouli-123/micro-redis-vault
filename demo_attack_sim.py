#!/usr/bin/env python3
"""
Brute-Force Attack Simulator for Micro-Redis-Vault Demo
======================================================
Simulates an aggressive credential-stuffing attacker attempting to guess
the vault passphrase, demonstrating live IP jailing & defense.
"""

import socket
import time
import sys

HOST = "127.0.0.1"
PORT = 6379

PASSWORDS = [
    "admin1", "123456", "password", "qwerty", "welcome",
    "secret", "letmein", "superman", "master1", "vaultpass"
]

def run_attack():
    print("\033[1;31m" + "=" * 60)
    print(" 🚨 LAUNCHING AUTOMATED BRUTE-FORCE ATTACK SIMULATION 🚨")
    print(f" Target: {HOST}:{PORT}")
    print(" Attack Vector: Passphrase Spraying (AUTH.PASSPHRASE)")
    print("=" * 60 + "\033[0m\n")

    for idx, pwd in enumerate(PASSWORDS):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.0)
            s.connect((HOST, PORT))
            
            cmd = f"AUTH.PASSPHRASE {pwd}\r\n"
            print(f"[\033[33mAttempt #{idx+1}\033[0m] Sending guess: '{pwd}' ...", end=" ", flush=True)
            s.sendall(cmd.encode('utf-8'))
            
            resp = s.recv(1024).decode('utf-8', errors='ignore').strip()
            if "JAILED" in resp or "IP is jailed" in resp:
                print(f"\n\033[1;41;37m 🛡️ DEFENSE TRIGGERED: {resp} \033[0m")
                print("\033[1;32m✅ SUCCESS: Micro-Redis-Vault has quarantined this IP address!\033[0m\n")
                s.close()
                break
            else:
                print(f"\033[31mREJECTED: {resp}\033[0m")
            s.close()
            time.sleep(0.3)
        except Exception as e:
            print(f"\033[31mConnection dropped by server: {e}\033[0m")
            break

if __name__ == "__main__":
    run_attack()
