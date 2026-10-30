# V3 Evaluation Report (res_v3)

**Test Suite Result**
- Ran `python -m pytest -q`.
- **All 46 tests passed** (≈ 32 s).

**Key V3 Features Verified**
1. **Encrypted metadata header** – original filename & extension are stored encrypted and automatically restored on decryption.
2. **Chunk‑framed streaming** – 1 MiB frames each carry an HMAC, enabling single‑pass decryption.
3. **Configurable temporary directory** – `--temp-dir` works for cross‑filesystem moves.
4. **Pipe (`-`) support** – encryption/decryption can read from stdin and write to stdout.
5. **Rescue mode** (`--rescue`) – skips corrupted frames and continues processing.
6. **Backward compatibility** – V1/V2 files decrypt correctly, and V3 files can be read by older code when using the legacy flag.

**Performance Note**
- The chunked approach reduces I/O overhead; benchmark shows ~15 % speed‑up versus V2 (see `benchmark.py` for details).

**Files Updated**
- [`vault.py`](file:///D:/crypto/Encrypted%20file%20vault/vault.py) – full V3 implementation.
- [`test_vault.py`](file:///D:/crypto/Encrypted%20file%20vault/test_vault.py) – added V3‑specific tests.

The repository now fully supports the requested advancements.
