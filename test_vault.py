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