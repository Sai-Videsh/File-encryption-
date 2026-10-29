# Encrypted File Vault

A command-line tool for password-based file encryption built with Python and the `cryptography` library.

Uses:
- **Key Derivation**: PBKDF2-HMAC-SHA256 (600,000 iterations, 16-byte random salt)
- **Encryption**: AES-256 in CTR mode (16-byte random nonce per file)
- **Integrity**: HMAC-SHA256 over header + ciphertext (encrypt-then-MAC)
- **Safe Output**: Atomic replacement via temporary files, chunked streaming (1 MB chunks).

## Installation

```bash
pip install -r requirements.txt
```

## Usage

### Encrypt a file
```bash
python vault.py encrypt <file>
```
Creates `<file>.vault`.

### Decrypt a file
```bash
python vault.py decrypt <file>.vault
```
Restores `<file>` (refuses to overwrite existing files unless `--force` is specified).

### Custom output path or force overwrite
```bash
python vault.py encrypt notes.txt -o my_backup.vault --force
python vault.py decrypt my_backup.vault -o notes_restored.txt --force
```

## Running Tests and Benchmarks

```bash
pytest -v
python benchmark.py
```
