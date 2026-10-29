# Encrypted File Vault: Complete Project Guide (Lean Version)

A command-line tool that encrypts and decrypts files with a password.
Built with Python and the `cryptography` library.
Uses PBKDF2-HMAC-SHA256, AES-256-CTR and HMAC-SHA256 (encrypt-then-MAC).

---

## 1. Project at a glance

| Item | Choice |
|---|---|
| Language | Python 3.10+ |
| Library | `cryptography` (never write AES yourself) |
| Interface | CLI: `vault encrypt <file>` and `vault decrypt <file>` |
| Key derivation | PBKDF2-HMAC-SHA256, 600,000 iterations, 16 byte random salt |
| Cipher | AES-256 in CTR mode, 16 byte random nonce per file |
| Integrity | HMAC-SHA256 over header + ciphertext (encrypt-then-MAC) |
| Keys | One 64 byte KDF output, split into 32 byte Enc key and 32 byte MAC key |
| Large files | Chunked processing (1 MB chunks), constant memory |
| Output safety | Temp file, then atomic rename. No partial output on failure |

### What the lean version delivers
- Confidentiality: nobody can read the file without the password.
- Integrity: any change to the file is caught before any plaintext is produced.
- Clean failure: wrong password, tampering, truncation and wrong file type all fail safely.

### Threat model (say this in your report and slide 2)
- Attacker has the encrypted file and unlimited time for offline password guessing.
- Attacker may modify the encrypted file.
- Out of scope: malware or keyloggers on the user's own machine, memory forensics, physical attacks on a running system.

---

## 2. Folder structure

```
encrypted-file-vault/
    vault.py            # the whole tool (CLI + crypto)
    test_vault.py       # pytest tests
    benchmark.py        # timing numbers for the results slides
    requirements.txt
    README.md           # short usage notes
```

`requirements.txt`:
```
cryptography>=42.0
pytest>=8.0
```

Setup:
```
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

---

## 3. Design

### 3.1 Encrypt flow
```
Password + random Salt
        |
     PBKDF2 (600,000 iterations)
        |
   64 bytes -> [Enc key 32B] [MAC key 32B]

File (read in chunks) -> AES-256-CTR (Enc key, random Nonce) -> Ciphertext
Header + Ciphertext -> HMAC-SHA256 (MAC key) -> Tag

Output file = Header | Ciphertext | Tag
```

### 3.2 Decrypt flow
```
Read header -> check magic, version, iteration range
Derive keys from password + salt in header
Pass 1: recompute HMAC over header + ciphertext, compare with stored tag
        mismatch -> stop, print generic error, write nothing
Pass 2: decrypt chunk by chunk into a temp file
        success -> rename temp file to final name
```
Pass 1 is what makes "verify before decrypt" true even for huge files.

### 3.3 File format (73 bytes of fixed overhead)

| Field | Size | Notes |
|---|---|---|
| Magic | 4 B | ASCII `EVLT`, identifies a vault file |
| Version | 1 B | `1`, lets the format change later |
| Iterations | 4 B | Big-endian, stored so old files still decrypt after tuning |
| Salt | 16 B | Random, not secret |
| Nonce | 16 B | Random, not secret |
| Ciphertext | N B | Same length as the plaintext (CTR needs no padding) |
| Tag | 32 B | HMAC-SHA256 over Header + Ciphertext |

Header size is 41 bytes, tag is 32 bytes, so overhead is 73 bytes per file.
The header is covered by the HMAC, so nobody can swap the salt, nonce or iteration count unnoticed.

### 3.4 Why these choices (know these for the viva)
- **PBKDF2 and not plain SHA-256:** a plain hash is fast, so guessing is cheap. PBKDF2 is slow on purpose.
- **Random salt per file:** same password gives a different key every time, and precomputed tables become useless.
- **Two keys:** using one key for both encryption and MAC can create weaknesses. Splitting the KDF output keeps the jobs separate.
- **CTR mode:** no padding, any file size, fast, works with streaming. Needs a never-repeating nonce.
- **Encrypt-then-MAC:** the tag covers the ciphertext, so tampering is caught before decryption touches it.
- **Same error for wrong password and tampering:** the tool cannot tell them apart anyway, and a different message would leak information.

---

## 4. Full code: `vault.py`

```python
#!/usr/bin/env python3
"""Encrypted File Vault: password-based file encryption.

PBKDF2-HMAC-SHA256 -> AES-256-CTR -> HMAC-SHA256 (encrypt-then-MAC).
"""
import argparse
import getpass
import os
import struct
import sys
import tempfile
import unicodedata

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

MAGIC = b"EVLT"
VERSION = 1
SALT_LEN = 16
NONCE_LEN = 16
TAG_LEN = 32
ITERATIONS = 600_000
MIN_ITER = 100_000        # reject absurdly low values in a header
MAX_ITER = 5_000_000      # reject values that could freeze the machine
CHUNK = 1024 * 1024       # 1 MB
HEADER_FMT = ">4sBI16s16s"  # magic, version, iterations, salt, nonce
HEADER_LEN = struct.calcsize(HEADER_FMT)  # 41
MIN_SIZE = HEADER_LEN + TAG_LEN
SUFFIX = ".vault"
GENERIC_FAIL = "Decryption failed: wrong password or the file was modified."


class VaultError(Exception):
    """Any expected failure. The message is safe to show to the user."""


def prep_password(pw: str) -> bytes:
    # Normalize so the same visible password always gives the same bytes.
    return unicodedata.normalize("NFKC", pw).encode("utf-8")


def derive_keys(password: bytes, salt: bytes, iterations: int):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=64,
        salt=salt,
        iterations=iterations,
    )
    okm = kdf.derive(password)
    return okm[:32], okm[32:]   # enc_key, mac_key


def _new_mac(mac_key: bytes):
    return hmac.HMAC(mac_key, hashes.SHA256())


def _temp_beside(dst: str):
    # Temp file in the same folder so os.replace is atomic.
    # mkstemp creates the file with owner-only permissions (0600).
    folder = os.path.dirname(os.path.abspath(dst))
    fd, path = tempfile.mkstemp(dir=folder, prefix=".vault-tmp-")
    return os.fdopen(fd, "wb"), path


def _check_paths(src: str, dst: str, force: bool):
    if not os.path.isfile(src):
        raise VaultError(f"Input file not found: {src}")
    if os.path.abspath(src) == os.path.abspath(dst):
        raise VaultError("Input and output must be different files.")
    if os.path.exists(dst) and not force:
        raise VaultError(f"Output already exists: {dst} (use --force to overwrite)")


def encrypt_file(src: str, dst: str, password: bytes, force: bool = False):
    _check_paths(src, dst, force)

    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    enc_key, mac_key = derive_keys(password, salt, ITERATIONS)

    header = struct.pack(HEADER_FMT, MAGIC, VERSION, ITERATIONS, salt, nonce)
    encryptor = Cipher(algorithms.AES(enc_key), modes.CTR(nonce)).encryptor()
    mac = _new_mac(mac_key)
    mac.update(header)

    fout, tmp = _temp_beside(dst)
    try:
        with open(src, "rb") as fin, fout:
            fout.write(header)
            while True:
                chunk = fin.read(CHUNK)
                if not chunk:
                    break
                ct = encryptor.update(chunk)
                mac.update(ct)
                fout.write(ct)
            fout.write(encryptor.finalize())  # empty for CTR
            fout.write(mac.finalize())
        os.replace(tmp, dst)
    except BaseException:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise


def decrypt_file(src: str, dst: str, password: bytes, force: bool = False):
    _check_paths(src, dst, force)

    size = os.path.getsize(src)
    if size < MIN_SIZE:
        raise VaultError("File is too short to be a vault file.")

    with open(src, "rb") as fin:
        header = fin.read(HEADER_LEN)
        magic, version, iters, salt, nonce = struct.unpack(HEADER_FMT, header)

        if magic != MAGIC:
            raise VaultError("Not a vault file.")
        if version != VERSION:
            raise VaultError(f"Unsupported vault version: {version}")
        if not (MIN_ITER <= iters <= MAX_ITER):
            raise VaultError(GENERIC_FAIL)

        enc_key, mac_key = derive_keys(password, salt, iters)
        body_len = size - HEADER_LEN - TAG_LEN

        # Pass 1: verify the tag BEFORE producing any plaintext.
        mac = _new_mac(mac_key)
        mac.update(header)
        remaining = body_len
        while remaining > 0:
            chunk = fin.read(min(CHUNK, remaining))
            if not chunk:
                raise VaultError(GENERIC_FAIL)
            mac.update(chunk)
            remaining -= len(chunk)
        tag = fin.read(TAG_LEN)
        try:
            mac.verify(tag)  # constant-time comparison
        except InvalidSignature:
            raise VaultError(GENERIC_FAIL) from None

        # Pass 2: decrypt into a temp file, rename only on success.
        fin.seek(HEADER_LEN)
        decryptor = Cipher(algorithms.AES(enc_key), modes.CTR(nonce)).decryptor()
        fout, tmp = _temp_beside(dst)
        try:
            with fout:
                remaining = body_len
                while remaining > 0:
                    chunk = fin.read(min(CHUNK, remaining))
                    if not chunk:
                        raise VaultError(GENERIC_FAIL)
                    fout.write(decryptor.update(chunk))
                    remaining -= len(chunk)
                fout.write(decryptor.finalize())
            os.replace(tmp, dst)
        except BaseException:
            if os.path.exists(tmp):
                os.remove(tmp)
            raise


def _default_output(cmd: str, path: str) -> str:
    if cmd == "encrypt":
        return path + SUFFIX
    if path.endswith(SUFFIX):
        return path[: -len(SUFFIX)]
    return path + ".dec"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="vault", description="Password-based file encryption."
    )
    sub = parser.add_subparsers(dest="cmd", required=True)
    for name in ("encrypt", "decrypt"):
        s = sub.add_parser(name, help=f"{name} a file")
        s.add_argument("input")
        s.add_argument("-o", "--output", help="output path")
        s.add_argument("--force", action="store_true", help="overwrite output")
    args = parser.parse_args(argv)

    try:
        out = args.output or _default_output(args.cmd, args.input)
        _check_paths(args.input, out, args.force)  # fail fast, before prompting

        if args.cmd == "encrypt":
            pw = getpass.getpass("Password: ")
            if not pw:
                raise VaultError("Password cannot be empty.")
            if len(pw) < 8:
                raise VaultError("Use at least 8 characters.")
            if getpass.getpass("Confirm password: ") != pw:
                raise VaultError("Passwords do not match.")
            if len(pw) < 12:
                print("Warning: a longer passphrase is much safer.", file=sys.stderr)
            encrypt_file(args.input, out, prep_password(pw), args.force)
            print(f"Encrypted -> {out}")
        else:
            pw = getpass.getpass("Password: ")
            decrypt_file(args.input, out, prep_password(pw), args.force)
            print(f"Decrypted -> {out}")
        return 0
    except VaultError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except OSError as e:
        print(f"File error: {e.strerror or e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nCancelled.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
```

Usage:
```
python vault.py encrypt notes.txt          # creates notes.txt.vault
python vault.py decrypt notes.txt.vault    # creates notes.txt (refuses to overwrite)
python vault.py decrypt notes.txt.vault -o restored.txt --force
```

---

## 5. Tests: `test_vault.py`

```python
import os

import pytest

import vault

PW = b"correct horse battery staple"


def write(path, data):
    path.write_bytes(data)
    return str(path)


@pytest.fixture
def enc_file(tmp_path):
    src = write(tmp_path / "a.bin", os.urandom(1000))
    enc = str(tmp_path / "a.bin.vault")
    vault.encrypt_file(src, enc, PW)
    return enc, str(tmp_path / "out.bin"), tmp_path


@pytest.mark.parametrize(
    "size",
    [0, 1, 15, 16, 17, vault.CHUNK - 1, vault.CHUNK, vault.CHUNK + 1, 3 * vault.CHUNK + 13],
)
def test_round_trip(tmp_path, size):
    data = os.urandom(size)
    src = write(tmp_path / "a.bin", data)
    enc = str(tmp_path / "a.vault")
    out = str(tmp_path / "a.out")
    vault.encrypt_file(src, enc, PW)
    vault.decrypt_file(enc, out, PW)
    assert open(out, "rb").read() == data


def test_overhead_is_fixed(tmp_path):
    src = write(tmp_path / "a.bin", b"x" * 500)
    enc = str(tmp_path / "a.vault")
    vault.encrypt_file(src, enc, PW)
    assert os.path.getsize(enc) == 500 + vault.HEADER_LEN + vault.TAG_LEN


def test_ciphertext_differs_from_plaintext(tmp_path):
    data = b"A" * 200
    src = write(tmp_path / "a.bin", data)
    enc = str(tmp_path / "a.vault")
    vault.encrypt_file(src, enc, PW)
    assert data not in open(enc, "rb").read()


def test_same_input_gives_different_output(tmp_path):
    src = write(tmp_path / "a.bin", b"hello world")
    e1, e2 = str(tmp_path / "1.vault"), str(tmp_path / "2.vault")
    vault.encrypt_file(src, e1, PW)
    vault.encrypt_file(src, e2, PW)
    assert open(e1, "rb").read() != open(e2, "rb").read()  # random salt and nonce


def test_wrong_password(enc_file):
    enc, out, tmp_path = enc_file
    with pytest.raises(vault.VaultError) as e:
        vault.decrypt_file(enc, out, b"wrong password here")
    assert str(e.value) == vault.GENERIC_FAIL
    assert not os.path.exists(out)


@pytest.mark.parametrize("offset", [0, 4, 5, 8, 9, 24, 25, 40, 41, 500, -33, -1])
def test_any_flipped_byte_is_rejected(enc_file, offset):
    enc, out, tmp_path = enc_file
    data = bytearray(open(enc, "rb").read())
    data[offset % len(data)] ^= 0x01
    open(enc, "wb").write(bytes(data))
    with pytest.raises(vault.VaultError):
        vault.decrypt_file(enc, out, PW)
    assert not os.path.exists(out)


@pytest.mark.parametrize("cut", [1, 32, 33, 100])
def test_truncated_file(enc_file, cut):
    enc, out, tmp_path = enc_file
    data = open(enc, "rb").read()
    open(enc, "wb").write(data[:-cut])
    with pytest.raises(vault.VaultError):
        vault.decrypt_file(enc, out, PW)
    assert not os.path.exists(out)


def test_tiny_file_rejected(tmp_path):
    src = write(tmp_path / "tiny.vault", b"EVLT")
    with pytest.raises(vault.VaultError):
        vault.decrypt_file(src, str(tmp_path / "o"), PW)


def test_not_a_vault_file(tmp_path):
    src = write(tmp_path / "x.txt", os.urandom(300))
    with pytest.raises(vault.VaultError, match="Not a vault file"):
        vault.decrypt_file(src, str(tmp_path / "o"), PW)


def test_missing_input(tmp_path):
    with pytest.raises(vault.VaultError, match="not found"):
        vault.encrypt_file(str(tmp_path / "nope"), str(tmp_path / "o"), PW)


def test_no_silent_overwrite(tmp_path):
    src = write(tmp_path / "a.bin", b"data")
    dst = write(tmp_path / "a.vault", b"precious")
    with pytest.raises(vault.VaultError, match="already exists"):
        vault.encrypt_file(src, dst, PW)
    assert open(dst, "rb").read() == b"precious"


def test_force_overwrite(tmp_path):
    src = write(tmp_path / "a.bin", b"data")
    dst = write(tmp_path / "a.vault", b"old")
    vault.encrypt_file(src, dst, PW, force=True)
    assert open(dst, "rb").read() != b"old"


def test_same_input_and_output(tmp_path):
    src = write(tmp_path / "a.bin", b"data")
    with pytest.raises(vault.VaultError):
        vault.encrypt_file(src, src, PW, force=True)


def test_no_temp_files_left_after_failure(enc_file):
    enc, out, tmp_path = enc_file
    with pytest.raises(vault.VaultError):
        vault.decrypt_file(enc, out, b"wrong password here")
    leftovers = [f for f in os.listdir(tmp_path) if f.startswith(".vault-tmp-")]
    assert leftovers == []


def test_unicode_password(tmp_path):
    pw = vault.prep_password("pässwörd-日本語-12345")
    src = write(tmp_path / "a.bin", b"secret")
    enc, out = str(tmp_path / "a.vault"), str(tmp_path / "a.out")
    vault.encrypt_file(src, enc, pw)
    vault.decrypt_file(enc, out, pw)
    assert open(out, "rb").read() == b"secret"
```

Run:
```
pytest -v
```
Take a screenshot of the passing run for the results slide. Count the real number of passed tests and use that number, do not invent one.

---

## 6. Benchmark: `benchmark.py`

```python
import os
import platform
import sys
import tempfile
import time

import vault

PW = b"benchmark password"


def bench_kdf():
    print("| Iterations | Time (ms) |")
    print("|---|---|")
    for it in (100_000, 300_000, 600_000, 1_000_000):
        t = time.perf_counter()
        vault.derive_keys(PW, os.urandom(16), it)
        ms = (time.perf_counter() - t) * 1000
        print(f"| {it:,} | {ms:.0f} |")


def bench_speed():
    print("\n| Size (MB) | Encrypt (s) | Decrypt (s) | Encrypt MB/s | Decrypt MB/s |")
    print("|---|---|---|---|---|")
    block = os.urandom(1024 * 1024)
    with tempfile.TemporaryDirectory() as d:
        for mb in (1, 10, 100, 500):
            src = os.path.join(d, "in.bin")
            enc = os.path.join(d, "in.vault")
            out = os.path.join(d, "out.bin")
            with open(src, "wb") as f:
                for _ in range(mb):
                    f.write(block)
            t = time.perf_counter()
            vault.encrypt_file(src, enc, PW, force=True)
            te = time.perf_counter() - t
            t = time.perf_counter()
            vault.decrypt_file(enc, out, PW, force=True)
            td = time.perf_counter() - t
            print(f"| {mb} | {te:.2f} | {td:.2f} | {mb/te:.1f} | {mb/td:.1f} |")


if __name__ == "__main__":
    print(f"Python {sys.version.split()[0]} on {platform.platform()}, CPU: {platform.processor()}\n")
    bench_kdf()
    bench_speed()
    print("\nNote: small files are dominated by the fixed KDF time (about 0.3 to 0.6 s).")
    print("Decrypt reads the file twice (verify, then decrypt), so it is a bit slower than encrypt.")
```

Run `python benchmark.py`, copy the real numbers into the charts, and write your CPU and Python version in a small caption on the slide.

---

## 7. Manual demo script (for the demo slide)

```
echo "this is a secret" > secret.txt
sha256sum secret.txt                         # note the hash
python vault.py encrypt secret.txt           # enter and confirm password
xxd secret.txt.vault | head                  # shows EVLT header then unreadable bytes
mv secret.txt secret_original.txt
python vault.py decrypt secret.txt.vault     # correct password
sha256sum secret.txt                         # hash must match the first one
python vault.py decrypt secret.txt.vault -o again.txt   # wrong password -> generic error
```
Take screenshots of: encrypt run, the hex view, matching hashes, and the wrong password failure.
On Windows use `certutil -hashfile secret.txt SHA256` instead of `sha256sum`.

---

## 8. Checks and edge cases

| Case | Expected behavior | Covered by |
|---|---|---|
| Normal file | Round trip returns identical bytes | `test_round_trip` |
| Empty file | Encrypts and decrypts to an empty file | `test_round_trip` size 0 |
| Size equal to, just under, just over the chunk size | Works | `test_round_trip` |
| Large file (500 MB) | Works with constant memory | `benchmark.py` |
| Wrong password | Generic error, no output file | `test_wrong_password` |
| Flipped bit in header, ciphertext or tag | Rejected, no output file | `test_any_flipped_byte_is_rejected` |
| Truncated file | Rejected, no output file | `test_truncated_file` |
| File shorter than header + tag | "Too short" error | `test_tiny_file_rejected` |
| Random non-vault file | "Not a vault file" | `test_not_a_vault_file` |
| Missing input file | Clear message | `test_missing_input` |
| Output already exists | Refused unless `--force` | `test_no_silent_overwrite` |
| Input equals output path | Refused | `test_same_input_and_output` |
| Interrupted run (Ctrl+C) | Temp file removed, final file untouched | cleanup in `except BaseException` |
| Same file encrypted twice | Different output each time | `test_same_input_gives_different_output` |
| Unicode password | Works, normalized with NFKC | `test_unicode_password` |
| Empty or short password | Rejected on encrypt | `main()` |
| Wrong version byte | "Unsupported version" | header check |
| Silly iteration count in header | Rejected before the KDF runs | `MIN_ITER` and `MAX_ITER` |

---

## 9. Safety rules (read before coding and before submitting)

### Must do
- Use `os.urandom` for salt and nonce. Never use `random`.
- Generate a new salt and a new nonce for every single encryption.
- Use separate keys for encryption and MAC (the 32 + 32 split).
- Compute the HMAC over header + ciphertext (encrypt-then-MAC).
- Verify the tag before producing any plaintext.
- Compare tags in constant time (`mac.verify` or `hmac.compare_digest`, never `==`).
- Show one generic message for wrong password and tampering.
- Write output to a temp file and rename only on success.
- Delete the temp file on every failure path, including Ctrl+C.
- Read the password with `getpass`, so it is not echoed or stored in shell history.
- Bound the iteration count read from the header.

### Must not do
- Do not pass the password on the command line (`--password secret`). It shows up in shell history and process lists.
- Do not hardcode a salt, nonce, key or password anywhere, including tests that look like examples.
- Do not reuse a nonce with the same key. In CTR this leaks the XOR of two plaintexts.
- Do not use MAC-then-encrypt, or skip the MAC.
- Do not decrypt first and check the tag afterwards.
- Do not print the password, the derived keys or the nonce in logs or error messages.
- Do not catch broad exceptions and continue silently.
- Do not use ECB mode, MD5 or SHA-1.
- Do not invent your own cipher, KDF or mode.

### Known limitations (state them honestly in the report)
- File size and timestamps are visible. Only the content is protected.
- A weak password can still be guessed offline. The slow KDF raises the cost but does not make weak passwords safe.
- No password recovery. A forgotten password means the data is gone.
- Secure deletion of the original file is unreliable on SSDs and journaling file systems, so the tool does not delete originals.
- Python cannot reliably wipe keys from memory.
- If someone changes the file while it is being decrypted (between the two passes), results are undefined. A local attacker with write access is out of scope.
- Malware or a keylogger on the same machine defeats any password-based tool.

---

## 10. Mapping to the 10 slides

| Slide | Content | Where in this guide |
|---|---|---|
| 1 | Cover | Section 1 |
| 2 | Problem, objectives, threat model, crypto basics table | Sections 1 and 3.4 |
| 3 | System design flowchart (encrypt and decrypt) | Sections 3.1 and 3.2 |
| 4 | Key derivation and encryption mode (CBC vs CTR table) | Sections 3.4 and 1 |
| 5 | Integrity with HMAC, decrypt flowchart | Sections 3.2 and 9 |
| 6 | File format byte bar | Section 3.3 |
| 7 | Demo screenshots and hash match | Section 7 |
| 8 | Test results table | Sections 5 and 8 |
| 9 | Performance charts and overhead | Section 6 |
| 10 | Security analysis, limitations, future work, conclusion | Sections 9 and 11 |

---

## 11. Add-ons after the lean version works (in order of value)

1. Both KDFs selectable (PBKDF2 and scrypt), with the choice stored in the header.
2. Both modes selectable (CBC with PKCS7 and CTR), with a speed and behavior comparison.
3. AES-GCM or ChaCha20-Poly1305 option, to compare with your manual encrypt-then-MAC.
4. Padding oracle demo against a CBC version without a MAC, then show the MAC blocks it.
5. Timing attack demo with naive `==` comparison versus constant-time comparison.
6. Argon2id support.
7. Keyfile support in addition to the password.
8. Folder encryption (tar, then encrypt).
9. Simple GUI with tkinter.

Fold any demo results from items 4 and 5 into the results slides instead of adding new slides.

---

## 12. Likely viva questions

1. Why not just hash the password with SHA-256 and use that as the key? (Too fast, so guessing is cheap, and no salt.)
2. Why is the salt stored in the file if it must be random? (It is not secret. Its job is uniqueness.)
3. Why a separate MAC key? (Keeps encryption and authentication independent, avoids cross-use weaknesses.)
4. What happens if the nonce repeats in CTR? (The same keystream is reused, so XOR of two ciphertexts equals XOR of two plaintexts.)
5. Why verify before decrypting? (Never process data that has not been authenticated. Also blocks padding oracle style attacks.)
6. Why the same error for wrong password and tampering? (Different messages would leak information, and the tool cannot distinguish them anyway.)
7. Is the header encrypted? (No, and it does not need to be. It holds no secret, but the HMAC protects it from modification.)
8. Why 600,000 iterations? (Current guidance for PBKDF2-HMAC-SHA256. It is stored in the header so it can be raised later.)
9. CBC vs CTR? (CBC needs padding and has an unpredictable IV rule. CTR needs no padding and a never-repeating nonce. Neither detects tampering alone.)
10. Can an attacker who modifies the iteration count break anything? (No. The header is covered by the HMAC, and the range is bounded to stop slowdown attacks.)

---

## 13. Time plan

| Task | Time |
|---|---|
| Write `vault.py` and test by hand | 3 to 5 hours |
| Write tests and fix bugs | 2 to 3 hours |
| Benchmark script and numbers | 1 hour |
| Screenshots and demo | 1 hour |
| Slides | 2 to 3 hours |
| Report and viva prep | 2 to 3 hours |
| Optional demo add-on (padding oracle or timing) | 3 to 4 hours |

---

## 14. Final submission checklist

- [ ] `vault.py` runs: encrypt and decrypt work on text, binary, empty and large files
- [ ] All tests pass, and you have a screenshot with the real count
- [ ] Benchmark run on your machine, real numbers on the slides, CPU and Python version noted
- [ ] No hardcoded secrets anywhere in the code
- [ ] Wrong password and tampered file give the same message and leave no output file
- [ ] No leftover `.vault-tmp-*` files after any failure
- [ ] README with install and usage steps
- [ ] `requirements.txt` included
- [ ] Slides: 10 or fewer, diagrams on design and file format slides, real results on result slides
- [ ] Limitations slide is honest
- [ ] You can explain every choice in section 3.4 and answer the questions in section 12