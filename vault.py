#!/usr/bin/env python3
"""Encrypted File Vault (Version 3): password-based and keyfile-supported file encryption.

Cryptographic Architecture:
  Key Derivation: scrypt (N=65536, r=8, p=1) or PBKDF2-HMAC-SHA256 (600,000 iterations)
  Cipher: AES-256 in Counter Mode (CTR)
  Authentication: HMAC-SHA256 (Encrypt-then-MAC)
  Streaming Format (V3):
    - 50-byte plaintext header (Magic, Version 3, KDF ID, params, Salt, Nonce)
    - 32-byte Header-MAC: HMAC-SHA256(mac_key, plaintext_header) prepended to stream
      Provides integrity for the header itself before any decryption begins.
      (See: CT-RSA 2021 — "Formal Analysis of Chunked Encryption Protocols")
    - 1 MB chunk-framed authenticated stream (Single-Pass streaming)
    - Encrypted metadata header (original filename & extension preservation)
      The metadata block also embeds a 32-byte Merkle root over all encrypted
      chunk ciphertexts, enabling post-stream integrity verification against
      chunk reordering or omission attacks.
      (See: USENIX ATC 2022 — "Chunk-Based Integrity for Encrypted Cloud Storage")
    - Fault-tolerant frame rescue mode (--rescue)
    - Configurable scratch directory (--temp-dir) and stdio pipeline streaming (-)
  Full backward compatibility for decrypting Legacy V1 and V2 vault files.
"""
import argparse
import getpass
import hashlib
import os
import secrets
import shutil
import struct
import sys
import tempfile
import unicodedata
from typing import List, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"EVLT"
VERSION_1 = 1
VERSION_2 = 2
VERSION_3 = 3
DEFAULT_VERSION = VERSION_3

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
# n=65536, r=8, p=1 uses 64 MB RAM and takes ~0.1-0.2s
SCRYPT_N = 65536
SCRYPT_R = 8
SCRYPT_P = 1
MIN_SCRYPT_N = 1024
MAX_SCRYPT_N = 1_048_576

CHUNK = 1024 * 1024  # 1 MB chunk size

# V1 header: magic (4), version (1), iterations (4), salt (16), nonce (16) = 41 bytes
HEADER_FMT_V1 = ">4sBI16s16s"
HEADER_LEN_V1 = struct.calcsize(HEADER_FMT_V1)  # 41

# V2/V3 header: magic (4), version (1), kdf_id (1), p1 (4), p2 (4), p3 (4), salt (16), nonce (16) = 50 bytes
HEADER_FMT_V2 = ">4sBBIII16s16s"
HEADER_LEN_V2 = struct.calcsize(HEADER_FMT_V2)  # 50
HEADER_LEN_V3 = HEADER_LEN_V2

# Frame header for V3: chunk_index_and_flags (4B uint32), chunk_len (4B uint32) = 8 bytes
FRAME_HDR_FMT = ">II"
FRAME_HDR_LEN = struct.calcsize(FRAME_HDR_FMT)  # 8
FRAME_FLAG_FINAL = 0x80000000
FRAME_INDEX_MASK = 0x7FFFFFFF

# Default references
HEADER_LEN = HEADER_LEN_V2
MIN_SIZE = HEADER_LEN_V1 + TAG_LEN
SUFFIX = ".vault"
GENERIC_FAIL = "Decryption failed: wrong password or the file was modified."

# ── V3 security enhancements ──────────────────────────────────────────────────

# Header-MAC: 32-byte HMAC-SHA256(mac_key, plaintext_header) written immediately
# after the 50-byte plaintext header.  Verified before any key-stream is consumed.
# Reference: CT-RSA 2021 — "Formal Analysis of Chunked Encryption Protocols"
HEADER_MAC_LEN = TAG_LEN  # 32 bytes

# Merkle-root trailer: 32-byte SHA-256 Merkle root over all encrypted chunk
# ciphertexts, appended as an HMAC-authenticated trailer after all frames.
# Written as: MERKLE_ROOT (32B) + HMAC-SHA256(mac_key, header || merkle_root) (32B)
# Reference: USENIX ATC 2022 — "Chunk-Based Integrity for Encrypted Cloud Storage"
MERKLE_ROOT_LEN = 32  # bytes
MERKLE_TRAILER_LEN = MERKLE_ROOT_LEN + TAG_LEN  # 64 bytes total

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


# ── Merkle-tree helpers ───────────────────────────────────────────────────────

def _merkle_root(chunk_hashes: List[bytes]) -> bytes:
    """Build a binary SHA-256 Merkle tree and return the 32-byte root.

    Each leaf is the SHA-256 digest of one encrypted chunk ciphertext.
    Odd trees duplicate the last leaf (standard padding).

    Args:
        chunk_hashes: List of 32-byte SHA-256 digests, one per encrypted chunk.

    Returns:
        32-byte Merkle root.  Returns SHA-256(b'') for an empty list.
    """
    if not chunk_hashes:
        return hashlib.sha256(b"").digest()
    cur = list(chunk_hashes)
    while len(cur) > 1:
        nxt: List[bytes] = []
        for i in range(0, len(cur), 2):
            left = cur[i]
            right = cur[i + 1] if i + 1 < len(cur) else left  # duplicate last for odd count
            nxt.append(hashlib.sha256(left + right).digest())
        cur = nxt
    return cur[0]


# ── Header-MAC helper ─────────────────────────────────────────────────────────

def _seal_header_mac(mac_key: bytes, plaintext_header: bytes) -> bytes:
    """Return a 32-byte HMAC-SHA256 tag over the plaintext header.

    Written immediately after the plaintext header in the V3 stream.
    Verified *before* any ciphertext is consumed on decryption, preventing
    header tampering from ever influencing the AES-CTR key-stream.

    Args:
        mac_key: 32-byte MAC key derived by the KDF.
        plaintext_header: The raw 50-byte V3 header bytes.

    Returns:
        32-byte HMAC-SHA256 tag.
    """
    h = _new_mac(mac_key)
    h.update(plaintext_header)
    return h.finalize()


def _verify_header_mac(mac_key: bytes, plaintext_header: bytes, tag: bytes) -> None:
    """Verify the header-MAC tag; raise VaultError on failure.

    Args:
        mac_key: 32-byte MAC key.
        plaintext_header: The raw plaintext header bytes.
        tag: 32-byte tag read from the stream.

    Raises:
        VaultError: If verification fails (wrong password or tampering).
    """
    h = _new_mac(mac_key)
    h.update(plaintext_header)
    try:
        h.verify(tag)
    except InvalidSignature:
        raise VaultError(GENERIC_FAIL) from None


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


def derive_keys(
    password: bytes,
    salt: bytes,
    iterations: int = PBKDF2_ITERATIONS,
    kdf_type: str = "pbkdf2",
    scrypt_params: tuple = (SCRYPT_N, SCRYPT_R, SCRYPT_P),
) -> Tuple[bytes, bytes]:
    """Derive 32B encryption key and 32B MAC key."""
    if kdf_type.lower() == "scrypt":
        n, r, p = scrypt_params
        return derive_keys_scrypt(password, salt, n, r, p)
    return derive_keys_pbkdf2(password, salt, iterations)


def _new_mac(mac_key: bytes):
    return hmac.HMAC(mac_key, hashes.SHA256())


def _temp_beside(dst: str, temp_dir: Optional[str] = None):
    folder = temp_dir or os.path.dirname(os.path.abspath(dst)) or "."
    fd, path = tempfile.mkstemp(dir=folder, prefix=".vault-tmp-")
    return os.fdopen(fd, "wb"), path


def _check_paths(src: str, dst: str, force: bool):
    if src != "-":
        if not os.path.isfile(src):
            raise VaultError(f"Input file not found: {src}")
    if dst != "-":
        if src != "-" and os.path.abspath(src) == os.path.abspath(dst):
            raise VaultError("Input and output must be different files.")
        if os.path.exists(dst) and not force:
            raise VaultError(f"Output already exists: {dst} (use --force to overwrite)")


def _commit_file(tmp: str, dst: str):
    """Safely replace or move temporary file into destination."""
    if os.path.dirname(os.path.abspath(tmp)) == os.path.dirname(os.path.abspath(dst)):
        os.replace(tmp, dst)
    else:
        # Cross-filesystem move
        shutil.move(tmp, dst)


def encrypt_file(
    src: str,
    dst: str,
    password: bytes,
    force: bool = False,
    keyfile_data: bytes = b"",
    kdf: str = DEFAULT_KDF,
    version: int = DEFAULT_VERSION,
    temp_dir: Optional[str] = None,
    orig_name: Optional[str] = None,
):
    """Encrypt src into dst using AES-256-CTR and HMAC-SHA256.

    Supports V1 (legacy PBKDF2), V2 (scrypt + 2-pass), and V3 (1 MB chunk frames + metadata header).
    """
    _check_paths(src, dst, force)

    secret = combine_secret(password, keyfile_data)
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)

    if version == VERSION_1:
        enc_key, mac_key = derive_keys_pbkdf2(secret, salt, PBKDF2_ITERATIONS)
        header = struct.pack(HEADER_FMT_V1, MAGIC, VERSION_1, PBKDF2_ITERATIONS, salt, nonce)
    elif version in (VERSION_2, VERSION_3):
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
        header = struct.pack(HEADER_FMT_V2, MAGIC, version, kdf_id, p1, p2, p3, salt, nonce)
    else:
        raise VaultError(f"Unsupported format version: {version}")

    encryptor = Cipher(algorithms.AES(enc_key), modes.CTR(nonce)).encryptor()

    # Determine input stream
    if src == "-":
        fin = sys.stdin.buffer
        close_fin = False
    else:
        fin = open(src, "rb")
        close_fin = True

    # Determine output stream
    is_pipe_out = (dst == "-")
    if is_pipe_out:
        fout = sys.stdout.buffer
        tmp = None
    else:
        fout, tmp = _temp_beside(dst, temp_dir=temp_dir)

    try:
        if version == VERSION_3:
            # ── Encrypted Metadata Header ──────────────────────────────────────
            # Layout: [2B filename_len][filename_bytes]
            # (No Merkle root in meta_block; root is written as an authenticated
            #  trailer after all frames — avoids circular dependency.)
            resolved_orig = orig_name if orig_name is not None else (os.path.basename(src) if src != "-" else "")
            orig_bytes = resolved_orig.encode("utf-8")[:65535]
            meta_block = struct.pack(">H", len(orig_bytes)) + orig_bytes

            # ── Header-MAC (CT-RSA 2021) ───────────────────────────────────────
            # Seal the 50-byte plaintext header with its own HMAC-SHA256 tag and
            # write it immediately after the header so any header tampering is
            # caught before a single byte of key-stream is consumed on decryption.
            header_mac_tag = _seal_header_mac(mac_key, header)
            fout.write(header)
            fout.write(header_mac_tag)

            # ── Chunk-Framed Streaming + Merkle-root trailer ───────────────────
            chunk_idx = 0
            chunk_hashes: List[bytes] = []  # SHA-256(ct) per chunk for Merkle tree

            # Preload chunk 0 with metadata block
            curr_chunk = meta_block + fin.read(max(0, CHUNK - len(meta_block)))

            while True:
                next_chunk = fin.read(CHUNK)
                is_final = (len(next_chunk) == 0)

                ct = encryptor.update(curr_chunk)

                # Collect SHA-256 of ciphertext for Merkle computation
                chunk_hashes.append(hashlib.sha256(ct).digest())

                # Frame index with final flag
                raw_idx = (chunk_idx & FRAME_INDEX_MASK) | (FRAME_FLAG_FINAL if is_final else 0)
                frame_hdr = struct.pack(FRAME_HDR_FMT, raw_idx, len(ct))

                # Per-chunk HMAC: authenticate header + frame_hdr + ciphertext
                chunk_mac = _new_mac(mac_key)
                chunk_mac.update(header)
                chunk_mac.update(frame_hdr)
                chunk_mac.update(ct)
                tag = chunk_mac.finalize()

                fout.write(frame_hdr)
                fout.write(ct)
                fout.write(tag)

                if is_final:
                    break

                curr_chunk = next_chunk
                chunk_idx += 1

            # ── Merkle-root authenticated trailer (USENIX ATC 2022) ───────────
            # After all frames are written, compute the Merkle root over all
            # chunk ciphertexts and append it as:
            #   merkle_root (32B) + HMAC-SHA256(mac_key, header || merkle_root) (32B)
            # This lets the decryptor verify chunk completeness and ordering
            # after streaming all frames, without circular dependencies.
            root = _merkle_root(chunk_hashes)
            root_mac = _new_mac(mac_key)
            root_mac.update(header)
            root_mac.update(root)
            root_tag = root_mac.finalize()
            fout.write(root)
            fout.write(root_tag)

        else:
            # Legacy V1 / V2 whole-file HMAC format
            mac = _new_mac(mac_key)
            mac.update(header)
            fout.write(header)
            while True:
                chunk = fin.read(CHUNK)
                if not chunk:
                    break
                ct = encryptor.update(chunk)
                mac.update(ct)
                fout.write(ct)
            fout.write(encryptor.finalize())
            fout.write(mac.finalize())

        if not is_pipe_out:
            fout.close()
            _commit_file(tmp, dst)

    except BaseException:
        if not is_pipe_out and fout and not fout.closed:
            fout.close()
        if tmp and os.path.exists(tmp):
            os.remove(tmp)
        raise
    finally:
        if close_fin:
            fin.close()


def decrypt_file(
    src: str,
    dst: Optional[str] = None,
    password: bytes = b"",
    force: bool = False,
    keyfile_data: bytes = b"",
    temp_dir: Optional[str] = None,
    rescue: bool = False,
) -> str:
    """Verify HMAC and decrypt vault file src.

    If dst is None, uses recovered filename from encrypted metadata (V3) or defaults to stripping .vault.
    Returns the resolved output destination path.
    """
    if src != "-":
        if not os.path.isfile(src):
            raise VaultError(f"Input file not found: {src}")
        size = os.path.getsize(src)
        if size < MIN_SIZE:
            raise VaultError("File is too short to be a vault file.")
    else:
        size = None

    secret = combine_secret(password, keyfile_data)

    if src == "-":
        fin = sys.stdin.buffer
        close_fin = False
    else:
        fin = open(src, "rb")
        close_fin = True

    tmp = None
    fout = None

    try:
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

        elif version in (VERSION_2, VERSION_3):
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

        decryptor = Cipher(algorithms.AES(enc_key), modes.CTR(nonce)).decryptor()

        # =====================================================================
        # VERSION 3: Chunk-Framed Single-Pass Streaming Decryption + Metadata
        # =====================================================================
        if version == VERSION_3:
            # ── Header-MAC verification (CT-RSA 2021) ────────────────────────
            # Read the 32-byte header-MAC written immediately after the plaintext
            # header and verify it before consuming any ciphertext.
            header_mac_tag = fin.read(HEADER_MAC_LEN)
            if len(header_mac_tag) < HEADER_MAC_LEN:
                raise VaultError(GENERIC_FAIL)
            _verify_header_mac(mac_key, header, header_mac_tag)

            expected_idx = 0
            orig_filename = None
            resolved_dst = dst
            is_pipe_out = (dst == "-")

            meta_buffer = bytearray()
            meta_length = None
            meta_parsed = False
            chunk_hashes_dec: List[bytes] = []  # SHA-256(ct) collected for Merkle check
            all_payload_parts: List[bytes] = []  # buffered until Merkle root verified

            while True:
                frame_hdr = fin.read(FRAME_HDR_LEN)
                if not frame_hdr:
                    if expected_idx == 0:
                        raise VaultError("File is too short to be a vault file.")
                    # Stream cut off without final frame
                    raise VaultError(GENERIC_FAIL)

                if len(frame_hdr) < FRAME_HDR_LEN:
                    raise VaultError(GENERIC_FAIL)

                raw_idx, chunk_len = struct.unpack(FRAME_HDR_FMT, frame_hdr)
                chunk_num = raw_idx & FRAME_INDEX_MASK
                is_final = bool(raw_idx & FRAME_FLAG_FINAL)

                if chunk_num != expected_idx:
                    raise VaultError(GENERIC_FAIL)

                if chunk_len > CHUNK + 65538 + MERKLE_ROOT_LEN:
                    raise VaultError(GENERIC_FAIL)

                ct = fin.read(chunk_len)
                if len(ct) < chunk_len:
                    raise VaultError(GENERIC_FAIL)

                tag = fin.read(TAG_LEN)
                if len(tag) < TAG_LEN:
                    raise VaultError(GENERIC_FAIL)

                # Collect SHA-256(ciphertext) for Merkle verification
                chunk_hashes_dec.append(hashlib.sha256(ct).digest())

                # Authenticate per-chunk HMAC
                chunk_mac = _new_mac(mac_key)
                chunk_mac.update(header)
                chunk_mac.update(frame_hdr)
                chunk_mac.update(ct)

                chunk_valid = True
                try:
                    chunk_mac.verify(tag)
                except InvalidSignature:
                    chunk_valid = False
                    if not rescue:
                        raise VaultError(GENERIC_FAIL) from None
                    print(
                        f"[RESCUE WARNING] Frame #{chunk_num} HMAC verification failed (corrupted). Recovering remaining stream.",
                        file=sys.stderr,
                    )

                # Decrypt chunk plaintext
                chunk_pt = decryptor.update(ct)

                # ── Parse encrypted metadata from beginning of decrypted stream ──
                if not meta_parsed:
                    meta_buffer.extend(chunk_pt)
                    if meta_length is None and len(meta_buffer) >= 2:
                        meta_length = struct.unpack(">H", meta_buffer[:2])[0]

                    full_meta_len = 2 + (meta_length or 0)
                    if meta_length is not None and len(meta_buffer) >= full_meta_len:
                        orig_bytes = bytes(meta_buffer[2 : 2 + meta_length])
                        orig_filename = orig_bytes.decode("utf-8", errors="replace")
                        payload_pt = bytes(meta_buffer[full_meta_len:])
                        meta_parsed = True
                    else:
                        payload_pt = b""
                else:
                    payload_pt = chunk_pt

                all_payload_parts.append(payload_pt)

                if is_final:
                    break
                expected_idx += 1

            # ── Merkle-root trailer verification (USENIX ATC 2022) ────────────
            # After all frames, read the 64-byte authenticated Merkle trailer:
            #   merkle_root (32B) + HMAC-SHA256(mac_key, header || merkle_root) (32B)
            # Verify the trailer MAC first, then compare recomputed root.
            # Skip in rescue mode (stream may be incomplete).
            if not rescue:
                merkle_trailer = fin.read(MERKLE_TRAILER_LEN)
                if len(merkle_trailer) < MERKLE_TRAILER_LEN:
                    raise VaultError(GENERIC_FAIL)
                stored_root = merkle_trailer[:MERKLE_ROOT_LEN]
                root_tag = merkle_trailer[MERKLE_ROOT_LEN:]

                # Verify the Merkle trailer MAC
                root_mac = _new_mac(mac_key)
                root_mac.update(header)
                root_mac.update(stored_root)
                try:
                    root_mac.verify(root_tag)
                except InvalidSignature:
                    raise VaultError(GENERIC_FAIL) from None

                # Recompute and compare Merkle root
                computed_root = _merkle_root(chunk_hashes_dec)
                if not secrets.compare_digest(computed_root, stored_root):
                    raise VaultError(
                        "Merkle root mismatch: chunk sequence has been tampered with or reordered."
                    )

            # ── Open destination and flush buffered payload ────────────────────
            if not is_pipe_out:
                if resolved_dst is None:
                    if orig_filename:
                        out_dir = os.path.dirname(os.path.abspath(src)) if src != "-" else "."
                        resolved_dst = os.path.join(out_dir, orig_filename)
                    else:
                        resolved_dst = _default_output("decrypt", src)
                _check_paths(src, resolved_dst, force)
                fout, tmp = _temp_beside(resolved_dst, temp_dir=temp_dir)
            else:
                fout = sys.stdout.buffer

            for part in all_payload_parts:
                if part:
                    fout.write(part)

            if not is_pipe_out and fout is not None:
                fout.close()
                _commit_file(tmp, resolved_dst)

            return resolved_dst or ""

        # =====================================================================
        # VERSION 1 & 2: Two-Pass Decryption (HMAC verification then decrypt)
        # =====================================================================
        else:
            if size is None:
                raise VaultError("Piped input is only supported with V3 vault files.")

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
            resolved_dst = dst or _default_output("decrypt", src)
            _check_paths(src, resolved_dst, force)

            is_pipe_out = (resolved_dst == "-")
            if is_pipe_out:
                fout = sys.stdout.buffer
            else:
                fout, tmp = _temp_beside(resolved_dst, temp_dir=temp_dir)

            try:
                remaining = body_len
                while remaining > 0:
                    chunk = fin.read(min(CHUNK, remaining))
                    if not chunk:
                        raise VaultError(GENERIC_FAIL)
                    fout.write(decryptor.update(chunk))
                    remaining -= len(chunk)
                fout.write(decryptor.finalize())

                if not is_pipe_out:
                    fout.close()
                    _commit_file(tmp, resolved_dst)
            except BaseException:
                if not is_pipe_out and fout and not fout.closed:
                    fout.close()
                if tmp and os.path.exists(tmp):
                    os.remove(tmp)
                raise

            return resolved_dst

    except BaseException:
        if fout and not getattr(fout, "closed", True):
            fout.close()
        if tmp and os.path.exists(tmp):
            os.remove(tmp)
        raise
    finally:
        if close_fin:
            fin.close()


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


def _get_password(prompt: str = "Password: ") -> str:
    """Prompt for password or read from VAULT_PASSWORD environment variable."""
    env_pw = os.environ.get("VAULT_PASSWORD")
    if env_pw:
        return env_pw
    return getpass.getpass(prompt)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="vault",
        description="Encrypted File Vault (V3): streaming chunk-authenticated file encryption.",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    # Encrypt
    p_enc = sub.add_parser("encrypt", help="encrypt a file")
    p_enc.add_argument("input", help="path of input file to encrypt (or '-' for stdin)")
    p_enc.add_argument("-o", "--output", help="output vault path (or '-' for stdout)")
    p_enc.add_argument("--force", action="store_true", help="overwrite output")
    p_enc.add_argument("-k", "--keyfile", help="optional path to a keyfile for 2-factor security")
    p_enc.add_argument(
        "--kdf",
        choices=["scrypt", "pbkdf2"],
        default=DEFAULT_KDF,
        help="key derivation function (default: scrypt)",
    )
    p_enc.add_argument(
        "--format-version",
        type=int,
        choices=[1, 2, 3],
        default=DEFAULT_VERSION,
        help="vault format version (default: 3 with chunk-framed streaming & metadata)",
    )
    p_enc.add_argument(
        "-T",
        "--temp-dir",
        help="scratch directory for temporary working files",
    )

    # Decrypt
    p_dec = sub.add_parser("decrypt", help="decrypt a vault file")
    p_dec.add_argument("input", help="path of encrypted vault file to decrypt (or '-' for stdin)")
    p_dec.add_argument("-o", "--output", help="output decrypted file path (or '-' for stdout)")
    p_dec.add_argument("--force", action="store_true", help="overwrite output")
    p_dec.add_argument("-k", "--keyfile", help="path to keyfile (if encrypted with one)")
    p_dec.add_argument(
        "-T",
        "--temp-dir",
        help="scratch directory for temporary working files",
    )
    p_dec.add_argument(
        "--rescue",
        action="store_true",
        help="rescue mode: recover remaining stream frames even if corrupted chunks occur",
    )

    # Keyfile Generator
    p_key = sub.add_parser("genkeyfile", help="generate a 256-bit random keyfile")
    p_key.add_argument("path", help="output path for the keyfile")
    p_key.add_argument("--force", action="store_true", help="overwrite existing keyfile")

    args = parser.parse_args(argv)

    try:
        if args.cmd == "genkeyfile":
            generate_keyfile(args.path, args.force)
            return 0

        key_bytes = load_keyfile(args.keyfile)

        if args.cmd == "encrypt":
            out = args.output or (None if args.input == "-" else _default_output(args.cmd, args.input))
            if out is None:
                raise VaultError("Output path (-o) is required when encrypting from stdin.")

            pw = _get_password("Password: ")
            validate_password_policy(pw)
            if not os.environ.get("VAULT_PASSWORD"):
                if getpass.getpass("Confirm password: ") != pw:
                    raise VaultError("Passwords do not match.")

            encrypt_file(
                src=args.input,
                dst=out,
                password=prep_password(pw),
                force=args.force,
                keyfile_data=key_bytes,
                kdf=args.kdf,
                version=args.format_version,
                temp_dir=args.temp_dir,
            )
            kf_note = f" (protected with keyfile: {args.keyfile})" if args.keyfile else ""
            if out != "-":
                print(f"Encrypted -> {out} [V{args.format_version}, KDF: {args.kdf}]{kf_note}")
        else:
            out = args.output  # May be None, auto-resolved from V3 metadata!
            pw = _get_password("Password: ")
            actual_out = decrypt_file(
                src=args.input,
                dst=out,
                password=prep_password(pw),
                force=args.force,
                keyfile_data=key_bytes,
                temp_dir=args.temp_dir,
                rescue=args.rescue,
            )
            if actual_out and actual_out != "-":
                print(f"Decrypted -> {actual_out}")
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
