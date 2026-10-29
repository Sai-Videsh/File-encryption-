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