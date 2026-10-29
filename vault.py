#!/usr/bin/env python3
"""Encrypted File Vault (Version 2): password-based and keyfile-supported file encryption.

KDF (scrypt or PBKDF2) -> AES-256-CTR -> HMAC-SHA256 (encrypt-then-MAC).
Supports selectable KDFs, keyfiles, 12+ char password enforcement, and legacy V1 decryption.
"""
import argparse
import getpass
import os
import struct
import sys
import tempfile
import unicodedata
from typing import Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"EVLT"
VERSION_1 = 1
VERSION_2 = 2
DEFAULT_VERSION = VERSION_2

SALT_LEN = 16
NONCE_LEN = 16
TAG_LEN = 32

# KDF identifiers
KDF_PBKDF2 = 0
KDF_SCRYPT = 1
DEFAULT_KDF = "scrypt"

# PBKDF2 parameters
PBKDF2_ITERATIONS = 600_000
MIN_PBKDF2_ITER = 100_000
MAX_PBKDF2_ITER = 5_000_000

# scrypt parameters (OWASP / RFC 7914 standard with robust memory cost)
# n=65536, r=8, p=1 uses 64 MB RAM and takes ~0.3-0.4s
SCRYPT_N = 65536
SCRYPT_R = 8
SCRYPT_P = 1
MIN_SCRYPT_N = 1024
MAX_SCRYPT_N = 1_048_576

CHUNK = 1024 * 1024  # 1 MB

# V1 header: magic (4), version (1), iterations (4), salt (16), nonce (16) = 41 bytes
HEADER_FMT_V1 = ">4sBI16s16s"
HEADER_LEN_V1 = struct.calcsize(HEADER_FMT_V1)  # 41

# V2 header: magic (4), version (1), kdf_id (1), p1 (4), p2 (4), p3 (4), salt (16), nonce (16) = 50 bytes
HEADER_FMT_V2 = ">4sBBIII16s16s"
HEADER_LEN_V2 = struct.calcsize(HEADER_FMT_V2)  # 50

# Default references
HEADER_LEN = HEADER_LEN_V2
MIN_SIZE = HEADER_LEN_V1 + TAG_LEN
SUFFIX = ".vault"
GENERIC_FAIL = "Decryption failed: wrong password or the file was modified."

COMMON_WEAK_PASSWORDS = {
    "password1234",
    "password12345",
    "123456789012",
    "qwertyuiop12",
    "admin12345678",
    "iloveyou12345",
    "welcome123456",
    "secret12345678",
    "monkey1234567",
    "dragon1234567",
    "master1234567",
    "football1234",
}


class VaultError(Exception):
    """Any expected failure. The message is safe to show to the user."""


def prep_password(pw: str) -> bytes:
    """Normalize password with NFKC so equivalent visible characters yield identical bytes."""
    return unicodedata.normalize("NFKC", pw).encode("utf-8")


def combine_secret(password: bytes, keyfile_data: bytes = b"") -> bytes:
    """Combine password and keyfile with domain separation."""
    if not keyfile_data:
        return password
    return password + b"\x00KEYFILE\x00" + keyfile_data


def load_keyfile(path: Optional[str]) -> bytes:
    """Read keyfile bytes safely."""
    if not path:
        return b""
    if not os.path.isfile(path):
        raise VaultError(f"Keyfile not found: {path}")
    try:
        with open(path, "rb") as f:
            data = f.read(1024 * 1024 + 1)  # cap read at 1 MB
        if not data:
            raise VaultError(f"Keyfile is empty: {path}")
        return data
    except OSError as e:
        raise VaultError(f"Failed to read keyfile: {e.strerror or e}")


def derive_keys_pbkdf2(secret: bytes, salt: bytes, iterations: int) -> Tuple[bytes, bytes]:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=64,
        salt=salt,
        iterations=iterations,
    )
    okm = kdf.derive(secret)
    return okm[:32], okm[32:]


def derive_keys_scrypt(secret: bytes, salt: bytes, n: int, r: int, p: int) -> Tuple[bytes, bytes]:
    kdf = Scrypt(
        salt=salt,
        length=64,
        n=n,
        r=r,
        p=p,
    )
    okm = kdf.derive(secret)
    return okm[:32], okm[32:]


def derive_keys(password: bytes, salt: bytes, iterations: int = PBKDF2_ITERATIONS,
                kdf_type: str = "pbkdf2", scrypt_params: tuple = (SCRYPT_N, SCRYPT_R, SCRYPT_P)) -> Tuple[bytes, bytes]:
    """Derive 32B encryption key and 32B MAC key."""
    if kdf_type.lower() == "scrypt":
        n, r, p = scrypt_params
        return derive_keys_scrypt(password, salt, n, r, p)
    return derive_keys_pbkdf2(password, salt, iterations)


def _new_mac(mac_key: bytes):
    return hmac.HMAC(mac_key, hashes.SHA256())


def _temp_beside(dst: str):
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


def encrypt_file(
    src: str,
    dst: str,
    password: bytes,
    force: bool = False,
    keyfile_data: bytes = b"",
    kdf: str = DEFAULT_KDF,
    version: int = DEFAULT_VERSION,
):
    """Encrypt src into dst using AES-256-CTR and HMAC-SHA256."""
    _check_paths(src, dst, force)

    secret = combine_secret(password, keyfile_data)
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)

    if version == VERSION_1:
        enc_key, mac_key = derive_keys_pbkdf2(secret, salt, PBKDF2_ITERATIONS)
        header = struct.pack(HEADER_FMT_V1, MAGIC, VERSION_1, PBKDF2_ITERATIONS, salt, nonce)
    elif version == VERSION_2:
        kdf_norm = kdf.lower()
        if kdf_norm == "scrypt":
            kdf_id = KDF_SCRYPT
            p1, p2, p3 = SCRYPT_N, SCRYPT_R, SCRYPT_P
            enc_key, mac_key = derive_keys_scrypt(secret, salt, p1, p2, p3)
        elif kdf_norm == "pbkdf2":
            kdf_id = KDF_PBKDF2
            p1, p2, p3 = PBKDF2_ITERATIONS, 0, 0
            enc_key, mac_key = derive_keys_pbkdf2(secret, salt, p1)
        else:
            raise VaultError(f"Unsupported KDF: {kdf}")
        header = struct.pack(HEADER_FMT_V2, MAGIC, VERSION_2, kdf_id, p1, p2, p3, salt, nonce)
    else:
        raise VaultError(f"Unsupported format version: {version}")

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


def decrypt_file(
    src: str,
    dst: str,
    password: bytes,
    force: bool = False,
    keyfile_data: bytes = b"",
):
    """Verify HMAC and decrypt vault file src into dst."""
    _check_paths(src, dst, force)

    size = os.path.getsize(src)
    if size < MIN_SIZE:
        raise VaultError("File is too short to be a vault file.")

    secret = combine_secret(password, keyfile_data)

    with open(src, "rb") as fin:
        magic = fin.read(4)
        if magic != MAGIC:
            raise VaultError("Not a vault file.")

        raw_ver = fin.read(1)
        if not raw_ver:
            raise VaultError("File is too short to be a vault file.")
        version = raw_ver[0]

        fin.seek(0)
        if version == VERSION_1:
            header = fin.read(HEADER_LEN_V1)
            if len(header) < HEADER_LEN_V1:
                raise VaultError("File is too short to be a vault file.")
            _, _, iters, salt, nonce = struct.unpack(HEADER_FMT_V1, header)
            if not (MIN_PBKDF2_ITER <= iters <= MAX_PBKDF2_ITER):
                raise VaultError(GENERIC_FAIL)
            enc_key, mac_key = derive_keys_pbkdf2(secret, salt, iters)
            header_len = HEADER_LEN_V1

        elif version == VERSION_2:
            header = fin.read(HEADER_LEN_V2)
            if len(header) < HEADER_LEN_V2:
                raise VaultError("File is too short to be a vault file.")
            _, _, kdf_id, p1, p2, p3, salt, nonce = struct.unpack(HEADER_FMT_V2, header)

            if kdf_id == KDF_PBKDF2:
                iters = p1
                if not (MIN_PBKDF2_ITER <= iters <= MAX_PBKDF2_ITER):
                    raise VaultError(GENERIC_FAIL)
                enc_key, mac_key = derive_keys_pbkdf2(secret, salt, iters)
            elif kdf_id == KDF_SCRYPT:
                n, r, p = p1, p2, p3
                # Validate bounds to prevent memory/CPU exhaustion DoS
                if not (MIN_SCRYPT_N <= n <= MAX_SCRYPT_N and (n & (n - 1)) == 0):
                    raise VaultError(GENERIC_FAIL)
                if not (1 <= r <= 16 and 1 <= p <= 8):
                    raise VaultError(GENERIC_FAIL)
                enc_key, mac_key = derive_keys_scrypt(secret, salt, n, r, p)
            else:
                raise VaultError(GENERIC_FAIL)
            header_len = HEADER_LEN_V2
        else:
            raise VaultError(f"Unsupported vault version: {version}")

        body_len = size - header_len - TAG_LEN
        if body_len < 0:
            raise VaultError("File is too short to be a vault file.")

        # Pass 1: verify HMAC tag BEFORE producing any plaintext
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
            mac.verify(tag)
        except InvalidSignature:
            raise VaultError(GENERIC_FAIL) from None

        # Pass 2: decrypt into temporary file, atomically rename on success
        fin.seek(header_len)
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


def generate_keyfile(path: str, force: bool = False):
    """Generate a high-entropy 32-byte random keyfile."""
    if os.path.exists(path) and not force:
        raise VaultError(f"Keyfile already exists: {path} (use --force to overwrite)")
    try:
        with open(path, "wb") as f:
            f.write(os.urandom(32))
        print(f"Generated 256-bit random keyfile -> {path}")
    except OSError as e:
        raise VaultError(f"Could not write keyfile: {e.strerror or e}")


def validate_password_policy(pw: str):
    """Enforce >= 12 characters and reject common weak passwords."""
    if not pw:
        raise VaultError("Password cannot be empty.")
    if len(pw) < 12:
        raise VaultError(
            f"Password is too short ({len(pw)} characters). Minimum requirement is 12 characters."
        )
    if pw.lower() in COMMON_WEAK_PASSWORDS:
        raise VaultError(
            "Password is too common and easily guessable. Please choose a unique passphrase."
        )


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="vault", description="Encrypted File Vault (V2): password & keyfile file encryption."
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    # Encrypt
    p_enc = sub.add_parser("encrypt", help="encrypt a file")
    p_enc.add_argument("input", help="path of input file to encrypt")
    p_enc.add_argument("-o", "--output", help="output vault path")
    p_enc.add_argument("--force", action="store_true", help="overwrite output")
    p_enc.add_argument("-k", "--keyfile", help="optional path to a keyfile for 2-factor security")
    p_enc.add_argument(
        "--kdf",
        choices=["scrypt", "pbkdf2"],
        default=DEFAULT_KDF,
        help="key derivation function (default: scrypt)",
    )

    # Decrypt
    p_dec = sub.add_parser("decrypt", help="decrypt a vault file")
    p_dec.add_argument("input", help="path of encrypted vault file to decrypt")
    p_dec.add_argument("-o", "--output", help="output decrypted file path")
    p_dec.add_argument("--force", action="store_true", help="overwrite output")
    p_dec.add_argument("-k", "--keyfile", help="path to keyfile (if encrypted with one)")

    # Keyfile Generator
    p_key = sub.add_parser("genkeyfile", help="generate a 256-bit random keyfile")
    p_key.add_argument("path", help="output path for the keyfile")
    p_key.add_argument("--force", action="store_true", help="overwrite existing keyfile")

    args = parser.parse_args(argv)

    try:
        if args.cmd == "genkeyfile":
            generate_keyfile(args.path, args.force)
            return 0

        out = args.output or _default_output(args.cmd, args.input)
        _check_paths(args.input, out, args.force)

        key_bytes = load_keyfile(args.keyfile)

        if args.cmd == "encrypt":
            pw = getpass.getpass("Password: ")
            validate_password_policy(pw)
            if getpass.getpass("Confirm password: ") != pw:
                raise VaultError("Passwords do not match.")

            encrypt_file(
                src=args.input,
                dst=out,
                password=prep_password(pw),
                force=args.force,
                keyfile_data=key_bytes,
                kdf=args.kdf,
                version=VERSION_2,
            )
            kf_note = f" (protected with keyfile: {args.keyfile})" if args.keyfile else ""
            print(f"Encrypted -> {out} [KDF: {args.kdf}]{kf_note}")
        else:
            pw = getpass.getpass("Password: ")
            decrypt_file(
                src=args.input,
                dst=out,
                password=prep_password(pw),
                force=args.force,
                keyfile_data=key_bytes,
            )
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
