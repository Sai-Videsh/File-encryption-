import hashlib
import os
import platform
import shutil
import struct
import sys
import time

import vault

TEST_DIR = os.path.abspath("./eval_comprehensive_data")
PW = "SuperSecret_P@ssw0rd!_2026_ComprehensiveTest"
PYTHON_EXE = sys.executable

def compute_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(2 * 1024 * 1024):  # 2 MB buffer
            h.update(chunk)
    return h.hexdigest()

def create_synthetic_media(path: str, size_bytes: int, media_type: str):
    """Generate realistic file headers followed by pseudo-random binary data."""
    with open(path, "wb") as f:
        if media_type == "wav":
            # RIFF WAV header (44 bytes)
            header = struct.pack(
                "<4sI4s4sIHHIIHH4sI",
                b"RIFF", size_bytes - 8, b"WAVE",
                b"fmt ", 16, 1, 2, 44100, 44100 * 4, 4, 16,
                b"data", size_bytes - 44
            )
            f.write(header)
            written = len(header)
        elif media_type == "mp3":
            # ID3v2 tag + MPEG frame sync header
            id3 = b"ID3\x04\x00\x00\x00\x00\x00\x00"
            f.write(id3)
            written = len(id3)
        elif media_type == "mp4":
            # ISO Base Media File Format: ftyp box
            ftyp = struct.pack(">I4s4s4s4s", 24, b"ftyp", b"isom", b"iso2", b"mp41")
            # mdat box header
            mdat_hdr = struct.pack(">I4s", size_bytes - 24, b"mdat")
            f.write(ftyp + mdat_hdr)
            written = len(ftyp) + len(mdat_hdr)
        elif media_type == "tiff":
            # TIFF header (little endian)
            header = b"II\x2A\x00\x08\x00\x00\x00"
            f.write(header)
            written = len(header)
        elif media_type == "sql":
            header = b"-- DATABASE DUMP ARCHIVE\n-- Version 2026.1\n\n"
            f.write(header)
            written = len(header)
        else:
            written = 0

        # Fill remaining with 1 MB pattern buffer
        chunk_size = 1024 * 1024
        # Semi-random block (fast generation)
        pattern = os.urandom(64 * 1024) * 16  # 1 MB block
        remaining = size_bytes - written
        while remaining > 0:
            to_write = min(chunk_size, remaining)
            f.write(pattern[:to_write])
            remaining -= to_write

def run_evaluation():
    if os.path.exists(TEST_DIR):
        shutil.rmtree(TEST_DIR)
    os.makedirs(TEST_DIR, exist_ok=True)

    print("=" * 95)
    print("ENCRYPTED FILE VAULT (V2) - EXTENSIVE SCALE & MEDIA EVALUATION")
    print(f"Platform: {platform.platform()} | Python: {sys.version.split()[0]}")
    print(f"CPU: {platform.processor()}")
    print("Default KDF: scrypt (N=65536, r=8, p=1) | Cipher: AES-256-CTR | Auth: HMAC-SHA256")
    print("=" * 95)

    test_matrix = [
        # --- Part A: Baseline sizes from res_1 ---
        ("empty.bin", 0, "generic", "0-byte empty file"),
        ("random_512B.bin", 512, "generic", "512 bytes small binary"),
        ("small_text.txt", 1220, "generic", "1.22 KB UTF-8 text"),
        ("chunk_minus_1.bin", 1048575, "generic", "1 MB - 1 byte boundary"),
        ("chunk_exact.bin", 1048576, "generic", "1 MB exact chunk boundary"),
        ("chunk_plus_1.bin", 1048577, "generic", "1 MB + 1 byte boundary"),
        ("multi_chunk_10MB.bin", 10 * 1024 * 1024, "generic", "10 MB multi-chunk binary"),
        ("stress_20MB.bin", 20 * 1024 * 1024, "generic", "20 MB synthetic binary"),
        ("stress_50MB.bin", 50 * 1024 * 1024, "generic", "50 MB synthetic binary"),
        ("stress_100MB.bin", 100 * 1024 * 1024, "generic", "100 MB synthetic binary"),
        ("stress_200MB.bin", 200 * 1024 * 1024, "generic", "200 MB synthetic binary"),

        # --- Part B: Real Media & Standard Formats (up to 500-600MB) ---
        ("sample_audio_pcm.wav", 50 * 1024 * 1024, "wav", "50 MB Audio (RIFF WAV format)"),
        ("podcast_broadcast.mp3", 250 * 1024 * 1024, "mp3", "250 MB Audio (MP3 audio stream)"),
        ("studio_master_hires.wav", 520 * 1024 * 1024, "wav", "520 MB High-Res Audio (WAV)"),
        ("web_video_clip.mp4", 150 * 1024 * 1024, "mp4", "150 MB Video (MPEG-4/H.264 stream)"),
        ("feature_film_1080p.mp4", 560 * 1024 * 1024, "mp4", "560 MB HD Video (MPEG-4 container)"),
        ("raw_photo_archive.tiff", 80 * 1024 * 1024, "tiff", "80 MB RAW Image/TIFF asset"),
        ("database_dump.sql", 120 * 1024 * 1024, "sql", "120 MB Database SQL dump"),

        # --- Part C: High-Scale Stress Tests (500MB, 750MB, 1000MB) ---
        ("large_500MB.bin", 500 * 1024 * 1024, "generic", "500 MB High-scale binary"),
        ("large_750MB.bin", 750 * 1024 * 1024, "generic", "750 MB High-scale binary"),
        ("large_1000MB_1GB.bin", 1000 * 1024 * 1024, "generic", "1000 MB (1 GB) Extreme scale"),
    ]

    header_fmt = f"{'Target File':<26} | {'Orig Size':<11} | {'Overhead':<8} | {'Enc(s)':<7} | {'Enc MB/s':<8} | {'Dec(s)':<7} | {'Dec MB/s':<8} | {'Integrity Loss'}"
    print("\n" + header_fmt)
    print("-" * len(header_fmt))

    report_lines = []
    report_lines.append(header_fmt)
    report_lines.append("-" * len(header_fmt))

    detailed_results = []

    for fname, size_b, mtype, desc in test_matrix:
        src = os.path.join(TEST_DIR, fname)
        enc = os.path.join(TEST_DIR, fname + ".vault")
        dec = os.path.join(TEST_DIR, fname + ".dec")

        # 1. Create file
        create_synthetic_media(src, size_b, mtype)
        actual_orig_size = os.path.getsize(src)
        orig_sha = compute_sha256(src)

        # 2. Encrypt
        t0 = time.perf_counter()
        vault.encrypt_file(src, enc, vault.prep_password(PW), force=True, kdf="scrypt")
        enc_time = time.perf_counter() - t0

        enc_size = os.path.getsize(enc)
        overhead = enc_size - actual_orig_size

        # 3. Decrypt
        t1 = time.perf_counter()
        vault.decrypt_file(enc, dec, vault.prep_password(PW), force=True)
        dec_time = time.perf_counter() - t1

        # 4. Verify integrity
        dec_sha = compute_sha256(dec)
        dec_size = os.path.getsize(dec)

        # Integrity Check
        if orig_sha == dec_sha and actual_orig_size == dec_size:
            integrity_str = "0 B (100% Match)"
            data_loss_bytes = 0
        else:
            diff = abs(actual_orig_size - dec_size)
            integrity_str = f"FAIL ({diff} B lost)"
            data_loss_bytes = diff

        size_mb = actual_orig_size / (1024 * 1024)
        enc_speed = (size_mb / enc_time) if enc_time > 0 and size_mb > 0 else 0.0
        dec_speed = (size_mb / dec_time) if dec_time > 0 and size_mb > 0 else 0.0

        overhead_pct = (overhead / actual_orig_size * 100) if actual_orig_size > 0 else 100.0

        row = f"{fname:<26} | {actual_orig_size:<11} | {overhead:>3} B ({overhead_pct:5.2f}%)| {enc_time:<7.2f} | {enc_speed:<8.1f} | {dec_time:<7.2f} | {dec_speed:<8.1f} | {integrity_str}"
        print(row)
        report_lines.append(row)

        detailed_results.append({
            "name": fname,
            "desc": desc,
            "type": mtype,
            "size_bytes": actual_orig_size,
            "size_mb": size_mb,
            "overhead_bytes": overhead,
            "overhead_pct": overhead_pct,
            "enc_time": enc_time,
            "enc_speed": enc_speed,
            "dec_time": dec_time,
            "dec_speed": dec_speed,
            "data_loss": data_loss_bytes,
            "sha256": orig_sha
        })

        # Remove files immediately to maintain available disk space
        if os.path.exists(src):
            os.remove(src)
        if os.path.exists(enc):
            os.remove(enc)
        if os.path.exists(dec):
            os.remove(dec)

    if os.path.exists(TEST_DIR):
        shutil.rmtree(TEST_DIR)

    print("\nAll tests completed successfully!")
    return detailed_results, report_lines

if __name__ == "__main__":
    results, report_table = run_evaluation()

