#!/usr/bin/env python3
"""Cloud deployment entrypoint for Micro-Redis-Vault."""
import os
import sys
from micro_redis_vault import main

if __name__ == "__main__":
    os.environ.setdefault("PORT", "8080")
    if "--web" not in sys.argv:
        sys.argv.append("--web")
    main()

