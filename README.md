# Encrypted File Vault (Version 2)

A production-grade command-line tool for password-based and two-factor file encryption built with Python and the `cryptography` library.

## Cryptographic Architecture

- **Key Derivation (KDF)**:
  - **`scrypt`** (Default for V2): $N=65536, r=8, p=1$ (memory-hard, resistant to GPU/ASIC password cracking).
  - **`PBKDF2-HMAC-SHA256`**: 600,000 iterations (selectable via `--kdf pbkdf2`).
  - **Bounded Parameters**: Header parameters validated within strict limits to eliminate DoS memory/CPU exhaustion attacks.
  - **Backward Compatibility**: Automatically detects and decrypts Version 1 vault files.
- **Two-Factor Authentication (2FA)**:
  - Supports physical keyfiles via `--keyfile / -k`. Password and keyfile are combined with domain separation.
  - Generator tool included: `python vault.py genkeyfile <path>`.
- **Cipher**: AES-256 in Counter (CTR) mode with 16-byte random nonce per file.
- **Integrity**: HMAC-SHA256 (Encrypt-then-MAC) covering the entire authenticated header and ciphertext.
- **Password Policy**:
  - Enforces minimum 12 characters.
  - Automatically rejects common weak passwords.
  - Unicode NFKC normalization ensures cross-platform consistency.
- **Safe Output**: Atomic replacement via temporary files (`mkstemp` + `os.replace`), 1 MB streaming chunks, constant memory ($O(1)$ RAM).

---

## Installation

```bash
pip install -r requirements.txt
```

---

## Usage Guide

### 1. Basic Encryption & Decryption
```bash
# Encrypt with scrypt (default)
python vault.py encrypt notes.txt

# Decrypt
python vault.py decrypt notes.txt.vault
```

### 2. Two-Factor Protection with Keyfile (Strongest Security)
```bash
# Generate a 256-bit random keyfile
python vault.py genkeyfile mykey.key

# Encrypt requiring both password AND keyfile
python vault.py encrypt notes.txt -k mykey.key

# Decrypt (fails without the keyfile)
python vault.py decrypt notes.txt.vault -k mykey.key
```

### 3. Selectable KDF
```bash
# Choose PBKDF2 instead of scrypt
python vault.py encrypt notes.txt --kdf pbkdf2
```

### 4. Custom Output Path & Force Overwrite
```bash
python vault.py encrypt notes.txt -o backup.vault --force
python vault.py decrypt backup.vault -o restored.txt --force
```

---

## Running the Automated Test Suite

```bash
python -m pytest test_vault.py -v
```
All 41 unit, edge-case, and adversarial tests will execute.
