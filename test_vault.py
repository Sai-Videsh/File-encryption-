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


def test_overhead_is_fixed_v2(tmp_path):
    src = write(tmp_path / "a.bin", b"x" * 500)
    enc = str(tmp_path / "a.vault")
    vault.encrypt_file(src, enc, PW, version=vault.VERSION_2)
    assert os.path.getsize(enc) == 500 + vault.HEADER_LEN_V2 + vault.TAG_LEN


def test_v3_overhead_and_metadata_structure(tmp_path):
    src = write(tmp_path / "sample.mp4", b"x" * 500)
    enc = str(tmp_path / "sample.vault")
    vault.encrypt_file(src, enc, PW, version=vault.VERSION_3)
    # V3 layout:
    #   50B  plaintext header
    #   32B  header-MAC tag
    #   8B   frame header
    #   2B   filename length field
    #   10B  'sample.mp4'
    #   500B payload ciphertext  (all in one chunk with meta)
    #   32B  per-chunk HMAC tag
    #   32B  Merkle root
    #   32B  Merkle root HMAC tag
    expected_size = (
        vault.HEADER_LEN_V3
        + vault.HEADER_MAC_LEN
        + vault.FRAME_HDR_LEN
        + (2 + len(b"sample.mp4"))
        + 500
        + vault.TAG_LEN
        + vault.MERKLE_TRAILER_LEN
    )
    assert os.path.getsize(enc) == expected_size


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


def test_kdf_scrypt_vs_pbkdf2_round_trip(tmp_path):
    data = b"Testing selectable KDFs in Version 2 and 3"
    src = write(tmp_path / "kdf_test.bin", data)
    pw = vault.prep_password("StrongP@ssphrase2026!")

    # Test scrypt
    enc_scrypt = str(tmp_path / "scrypt.vault")
    out_scrypt = str(tmp_path / "scrypt.out")
    vault.encrypt_file(src, enc_scrypt, pw, kdf="scrypt")
    vault.decrypt_file(enc_scrypt, out_scrypt, pw)
    assert open(out_scrypt, "rb").read() == data

    # Test PBKDF2
    enc_pbkdf2 = str(tmp_path / "pbkdf2.vault")
    out_pbkdf2 = str(tmp_path / "pbkdf2.out")
    vault.encrypt_file(src, enc_pbkdf2, pw, kdf="pbkdf2")
    vault.decrypt_file(enc_pbkdf2, out_pbkdf2, pw)
    assert open(out_pbkdf2, "rb").read() == data


def test_legacy_version_1_compatibility(tmp_path):
    data = b"V1 legacy data verification"
    src = write(tmp_path / "v1.bin", data)
    enc = str(tmp_path / "v1.vault")
    out = str(tmp_path / "v1.out")
    pw = vault.prep_password("StrongP@ssphrase2026!")

    # Explicitly encrypt with V1
    vault.encrypt_file(src, enc, pw, version=vault.VERSION_1)
    assert os.path.getsize(enc) == len(data) + vault.HEADER_LEN_V1 + vault.TAG_LEN

    # Decrypt with unified decryptor
    vault.decrypt_file(enc, out, pw)
    assert open(out, "rb").read() == data


def test_legacy_version_2_compatibility(tmp_path):
    data = b"V2 legacy data with scrypt and 2-pass"
    src = write(tmp_path / "v2.bin", data)
    enc = str(tmp_path / "v2.vault")
    out = str(tmp_path / "v2.out")
    pw = vault.prep_password("StrongP@ssphrase2026!")

    vault.encrypt_file(src, enc, pw, version=vault.VERSION_2)
    assert os.path.getsize(enc) == len(data) + vault.HEADER_LEN_V2 + vault.TAG_LEN

    vault.decrypt_file(enc, out, pw)
    assert open(out, "rb").read() == data


def test_v3_auto_restore_filename_and_extension(tmp_path):
    src = write(tmp_path / "my_secret_video.mp4", b"BinaryVideoData123456")
    enc = str(tmp_path / "encrypted_container.vault")
    vault.encrypt_file(src, enc, PW)

    # Delete original source file to simulate true recovery in clean folder
    os.remove(src)

    # Decrypt without dst specified -> auto-restores original filename and content!
    recovered_path = vault.decrypt_file(enc, None, PW)
    assert os.path.basename(recovered_path) == "my_secret_video.mp4"
    assert open(recovered_path, "rb").read() == b"BinaryVideoData123456"


def test_configurable_temp_dir(tmp_path):
    custom_temp = tmp_path / "scratch_dir"
    custom_temp.mkdir()
    src = write(tmp_path / "data.bin", b"test data for temp dir")
    enc = str(tmp_path / "data.vault")
    out = str(tmp_path / "data.out")

    vault.encrypt_file(src, enc, PW, temp_dir=str(custom_temp))
    vault.decrypt_file(enc, out, PW, temp_dir=str(custom_temp))
    assert open(out, "rb").read() == b"test data for temp dir"


def test_v3_rescue_mode(tmp_path):
    chunk1 = b"A" * vault.CHUNK
    chunk2 = b"B" * 1000
    src = write(tmp_path / "stream.bin", chunk1 + chunk2)
    enc = str(tmp_path / "stream.vault")
    out = str(tmp_path / "stream.out")
    vault.encrypt_file(src, enc, PW)

    raw = bytearray(open(enc, "rb").read())
    # Corrupt last frame's HMAC tag
    raw[-5] ^= 0xFF
    open(enc, "wb").write(bytes(raw))

    with pytest.raises(vault.VaultError):
        vault.decrypt_file(enc, out, PW, rescue=False)

    vault.decrypt_file(enc, out, PW, rescue=True)
    res = open(out, "rb").read()
    assert res.startswith(chunk1)


def test_keyfile_support(tmp_path):
    data = b"Confidential Two-Factor Protected Data"
    src = write(tmp_path / "data.bin", data)
    enc = str(tmp_path / "data.vault")
    out = str(tmp_path / "data.out")
    pw = vault.prep_password("StrongP@ssphrase2026!")

    # Generate keyfile
    kf_path = str(tmp_path / "user.key")
    vault.generate_keyfile(kf_path)
    key_bytes = vault.load_keyfile(kf_path)
    assert len(key_bytes) == 32

    # Encrypt with password + keyfile
    vault.encrypt_file(src, enc, pw, keyfile_data=key_bytes)

    # Decrypt without keyfile -> MUST FAIL
    with pytest.raises(vault.VaultError) as exc:
        vault.decrypt_file(enc, out, pw, keyfile_data=b"")
    assert str(exc.value) == vault.GENERIC_FAIL
    assert not os.path.exists(out)

    # Decrypt with WRONG keyfile -> MUST FAIL
    wrong_key = os.urandom(32)
    with pytest.raises(vault.VaultError) as exc:
        vault.decrypt_file(enc, out, pw, keyfile_data=wrong_key)
    assert str(exc.value) == vault.GENERIC_FAIL
    assert not os.path.exists(out)

    # Decrypt with CORRECT keyfile -> SUCCESS
    vault.decrypt_file(enc, out, pw, keyfile_data=key_bytes)
    assert open(out, "rb").read() == data


def test_password_policy():
    # Less than 12 chars rejected
    with pytest.raises(vault.VaultError, match="too short"):
        vault.validate_password_policy("short99")

    # Common weak password rejected
    with pytest.raises(vault.VaultError, match="too common"):
        vault.validate_password_policy("password1234")

    # 12+ chars valid passphrase accepted
    vault.validate_password_policy("valid-strong-passphrase-2026")


# ── Header-MAC tests (CT-RSA 2021) ───────────────────────────────────────────

def test_header_mac_present_and_correct(tmp_path):
    """Header-MAC tag must be present and verify cleanly on a fresh encrypt."""
    src = write(tmp_path / "a.bin", b"hello vault")
    enc = str(tmp_path / "a.vault")
    vault.encrypt_file(src, enc, PW)
    raw = open(enc, "rb").read()
    # Bytes [50:82] are the header-MAC tag
    header_bytes = raw[:vault.HEADER_LEN_V3]
    tag = raw[vault.HEADER_LEN_V3 : vault.HEADER_LEN_V3 + vault.HEADER_MAC_LEN]
    assert len(tag) == vault.HEADER_MAC_LEN
    # Re-derive keys and recompute to confirm it matches
    _, _, kdf_id, p1, p2, p3, salt, nonce = vault.struct.unpack(vault.HEADER_FMT_V2, header_bytes)
    _, mac_key = vault.derive_keys_scrypt(PW, salt, p1, p2, p3)
    import hmac as _hmac, hashlib
    expected = _hmac.new(mac_key, header_bytes, hashlib.sha256).digest()
    assert _hmac.compare_digest(tag, expected)


def test_tampered_header_is_rejected(tmp_path):
    """Flipping any byte in the 50-byte plaintext header must fail Header-MAC check."""
    src = write(tmp_path / "a.bin", b"sensitive data in vault")
    enc = str(tmp_path / "a.vault")
    out = str(tmp_path / "a.out")
    vault.encrypt_file(src, enc, PW)

    raw = bytearray(open(enc, "rb").read())
    # Flip a byte inside the plaintext header (byte 10, inside salt region)
    raw[10] ^= 0xFF
    open(enc, "wb").write(bytes(raw))

    with pytest.raises(vault.VaultError, match=vault.GENERIC_FAIL):
        vault.decrypt_file(enc, out, PW)
    assert not os.path.exists(out)


def test_tampered_header_mac_tag_is_rejected(tmp_path):
    """Flipping any byte in the Header-MAC tag itself must fail verification."""
    src = write(tmp_path / "a.bin", b"another secret")
    enc = str(tmp_path / "a.vault")
    out = str(tmp_path / "a.out")
    vault.encrypt_file(src, enc, PW)

    raw = bytearray(open(enc, "rb").read())
    # Flip a byte inside the Header-MAC tag region [50:82]
    raw[vault.HEADER_LEN_V3 + 5] ^= 0xAA
    open(enc, "wb").write(bytes(raw))

    with pytest.raises(vault.VaultError):
        vault.decrypt_file(enc, out, PW)
    assert not os.path.exists(out)


# ── Merkle-root tests (USENIX ATC 2022) ──────────────────────────────────────

def test_merkle_root_detects_chunk_omission(tmp_path):
    """Truncating a middle frame must be caught by Merkle root mismatch."""
    # Two chunks: chunk 0 (1 MB) + chunk 1 (small)
    data = b"X" * vault.CHUNK + b"Y" * 500
    src = write(tmp_path / "big.bin", data)
    enc = str(tmp_path / "big.vault")
    out = str(tmp_path / "big.out")
    vault.encrypt_file(src, enc, PW)

    # Remove chunk 1 by truncating the file right after chunk 0's tag
    # Offset: header(50) + header-mac(32) + frame0(8 + chunk0_ct_len + 32)
    raw = open(enc, "rb").read()
    # Find frame 0 end: header + header_mac + frame_hdr + ct + tag
    offset = vault.HEADER_LEN_V3 + vault.HEADER_MAC_LEN
    fh_raw_idx, fh_chunk_len = vault.struct.unpack(vault.FRAME_HDR_FMT, raw[offset: offset + vault.FRAME_HDR_LEN])
    frame0_end = offset + vault.FRAME_HDR_LEN + fh_chunk_len + vault.TAG_LEN
    # Write only up to end of frame 0, with final flag patched in
    raw_trunc = bytearray(raw[:frame0_end])
    # Patch frame 0 raw_idx to set FINAL flag so parser accepts it
    raw_idx_patched = (fh_raw_idx & vault.FRAME_INDEX_MASK) | vault.FRAME_FLAG_FINAL
    vault.struct.pack_into(vault.FRAME_HDR_FMT, raw_trunc, offset, raw_idx_patched, fh_chunk_len)
    open(enc, "wb").write(bytes(raw_trunc))

    with pytest.raises(vault.VaultError):
        vault.decrypt_file(enc, out, PW)
    assert not os.path.exists(out)


def test_merkle_root_consistent_after_round_trip(tmp_path):
    """A clean round-trip must pass Merkle-root verification without error."""
    data = b"A" * vault.CHUNK + b"B" * vault.CHUNK + b"C" * 123
    src = write(tmp_path / "multi.bin", data)
    enc = str(tmp_path / "multi.vault")
    out = str(tmp_path / "multi.out")
    vault.encrypt_file(src, enc, PW)
    vault.decrypt_file(enc, out, PW)
    assert open(out, "rb").read() == data


def test_merkle_helper_single_leaf(tmp_path):
    """_merkle_root of a single leaf must equal SHA-256 of that leaf."""
    import hashlib
    leaf = hashlib.sha256(b"one chunk").digest()
    root = vault._merkle_root([leaf])
    assert root == leaf


def test_merkle_helper_two_leaves(tmp_path):
    """_merkle_root of two leaves must equal SHA-256(leaf0 + leaf1)."""
    import hashlib
    l0 = hashlib.sha256(b"chunk0").digest()
    l1 = hashlib.sha256(b"chunk1").digest()
    root = vault._merkle_root([l0, l1])
    assert root == hashlib.sha256(l0 + l1).digest()


def test_merkle_helper_empty():
    """_merkle_root of empty list must return SHA-256(b'')."""
    import hashlib
    assert vault._merkle_root([]) == hashlib.sha256(b"").digest()
