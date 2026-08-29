#!/usr/bin/env bash
# ==============================================================================
# Deterministic Reproducible Build Script for Micro-Redis-Vault
# Verifies zero runtime dependencies and generates SHA-256 byte checksums.
# ==============================================================================

set -e

echo "=================================================================="
echo " 🛠️  MICRO-REDIS-VAULT REPRODUCIBLE BUILD & VERIFICATION SCRIPT"
echo "=================================================================="

# 1. Dependency Manifest Verification
echo "[1/4] Checking dependency manifests..."
if [ -s requirements.txt ]; then
    echo "❌ Error: requirements.txt is not empty!"
    exit 1
else
    echo "✅ Success: requirements.txt is 0 bytes (Zero third-party dependencies)."
fi

# 2. Syntax & Compilation Verification
echo "[2/4] Verifying Python syntax and byte-compilation..."
python3 -m py_compile micro_redis_vault.py

# 3. Automated Test Suite Execution
echo "[3/4] Running automated test suite..."
python3 test_micro_redis_vault.py

# 4. Deterministic Hash Generation (Reproducible Build Bonus)
echo "[4/4] Computing SHA-256 Checksums for reproducible build verification:"
echo "------------------------------------------------------------------"
sha256sum micro_redis_vault.py
sha256sum test_micro_redis_vault.py
echo "------------------------------------------------------------------"
echo "🎉 Build verification PASSED with ZERO dependencies!"
