import hashlib
import math
import os
import struct
import sys
import time
import wave

import vault

OUTPUT_DIR = os.path.abspath("./real_media_test")
PW = b"CorrectHorseBatteryStaple2026!"

def compute_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(2 * 1024 * 1024):
            h.update(chunk)
    return h.hexdigest()

def generate_real_audio(filepath: str, duration_sec: int = 150):
    """
    Generates a 100% REAL, playable stereo WAV audio file.
    Creates rich harmonic acoustic musical chords (C major chord: 261.6Hz, 329.6Hz, 392.0Hz).
    Plays in Windows Media Player, VLC, Groove Music, etc.
    """
    sample_rate = 44100
    total_frames = sample_rate * duration_sec
    print(f"Generating real playable audio ({duration_sec}s stereo @ 44.1kHz) -> {filepath}...")

    with wave.open(filepath, "wb") as wav:
        wav.setnchannels(2)      # Stereo
        wav.setsampwidth(2)      # 16-bit
        wav.setframerate(sample_rate)

        # Generate frames in 1-second chunks for fast memory-efficient writing
        chunk_frames = sample_rate
        for sec in range(duration_sec):
            buf = bytearray()
            for i in range(chunk_frames):
                t = (sec * sample_rate + i) / sample_rate
                # Harmonic chord with slow frequency modulation
                f1 = 261.63 + 10 * math.sin(2 * math.pi * 0.1 * t) # C4
                f2 = 329.63 # E4
                f3 = 392.00 # G4
                # Stereo panning: left channel C+E, right channel E+G
                sample_l = int(12000 * (0.6 * math.sin(2 * math.pi * f1 * t) + 0.4 * math.sin(2 * math.pi * f2 * t)))
                sample_r = int(12000 * (0.6 * math.sin(2 * math.pi * f3 * t) + 0.4 * math.sin(2 * math.pi * f2 * t)))
                buf.extend(struct.pack("<hh", sample_l, sample_r))
            wav.writeframes(buf)
    print(f"  -> Created audio: {os.path.getsize(filepath) / (1024*1024):.1f} MB")

def generate_real_image(filepath: str, width: int = 4800, height: int = 3600):
    """
    Generates a 100% REAL, high-resolution viewable Windows Bitmap (.bmp) image.
    Resolution: 4800x3600 (17.2 Megapixels).
    Draws a 24-bit RGB mathematical color gradient with geometric pattern.
    Opens natively in Windows Photos, Paint, and browser.
    """
    print(f"Generating real viewable image ({width}x{height} RGB) -> {filepath}...")
    row_size = (width * 3 + 3) & ~3  # 4-byte row alignment
    image_data_size = row_size * height
    file_size = 54 + image_data_size

    # BMP File Header (14 bytes) + DIB Header (40 bytes)
    bmp_header = struct.pack("<2sIHHI", b"BM", file_size, 0, 0, 54)
    dib_header = struct.pack("<IiiHHIIiiII", 40, width, height, 1, 24, 0, image_data_size, 2835, 2835, 0, 0)

    with open(filepath, "wb") as f:
        f.write(bmp_header)
        f.write(dib_header)

        # Write rows
        for y in range(height):
            row = bytearray(row_size)
            g = int((y / height) * 255)
            for x in range(width):
                r = int((x / width) * 255)
                b = int(((x ^ y) % 256))
                # BMP pixel format is BGR
                idx = x * 3
                row[idx] = b
                row[idx + 1] = g
                row[idx + 2] = r
            f.write(row)
    print(f"  -> Created image: {os.path.getsize(filepath) / (1024*1024):.1f} MB")

def generate_real_video(filepath: str, width: int = 640, height: int = 480, fps: int = 30, num_frames: int = 300):
    """
    Generates a 100% REAL, playable uncompressed DIB AVI video (.avi).
    Length: 10 seconds (300 frames @ 30 FPS).
    Renders moving chromatic visual waves across each frame.
    Plays natively in Windows Media Player and VLC!
    """
    print(f"Generating real playable video ({width}x{height} @ {fps}fps, {num_frames} frames) -> {filepath}...")
    frame_size = width * height * 3
    usec = int(1_000_000 / fps)

    avih = struct.pack('<4sI14I', b'avih', 56, usec, frame_size * fps, 0, 0x10, num_frames, 0, 1, frame_size, width, height, 0, 0, 0, 0)
    strh_data = struct.pack('<4s4sIIIIIIIIIIhhhh', b'vids', b'DIB ', 0, 0, 0, 1, fps, 0, num_frames, frame_size, 0, 0, 0, 0, width, height)
    strh = struct.pack('<4sI', b'strh', len(strh_data)) + strh_data
    strf_data = struct.pack('<IiiHHIIiiII', 40, width, height, 1, 24, 0, frame_size, 0, 0, 0, 0)
    strf = struct.pack('<4sI', b'strf', len(strf_data)) + strf_data

    strl_data = strh + strf
    strl = struct.pack('<4sI4s', b'LIST', len(strl_data) + 4, b'strl') + strl_data
    hdrl_data = avih + strl
    hdrl = struct.pack('<4sI4s', b'LIST', len(hdrl_data) + 4, b'hdrl') + hdrl_data

    movi_size = 4 + num_frames * (8 + frame_size)
    riff_size = 4 + len(hdrl) + 8 + movi_size

    with open(filepath, "wb") as f:
        f.write(struct.pack('<4sI4s', b'RIFF', riff_size, b'AVI '))
        f.write(hdrl)
        f.write(struct.pack('<4sI4s', b'LIST', movi_size, b'movi'))

        for i in range(num_frames):
            # Animated chromatic wave pattern per frame
            r = int((math.sin(i * 0.05) + 1) * 127)
            g = int((math.cos(i * 0.07) + 1) * 127)
            b = int((math.sin(i * 0.09 + 1) + 1) * 127)
            color = bytes([b, g, r])
            frame_data = color * (width * height)

            f.write(b'00db')
            f.write(struct.pack('<I', frame_size))
            f.write(frame_data)
    print(f"  -> Created video: {os.path.getsize(filepath) / (1024*1024):.1f} MB")

def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    print("=" * 80)
    print("REAL PLAYABLE & VIEWABLE MEDIA TEST GENERATOR")
    print(f"Saving permanent files to: {OUTPUT_DIR}")
    print("ALL CLEANUP / DELETION COMMANDS ARE COMPLETELY DISABLED / COMMENTED OUT.")
    print("=" * 80)

    audio_file = os.path.join(OUTPUT_DIR, "real_soundtrack.wav")
    image_file = os.path.join(OUTPUT_DIR, "real_graphic.bmp")
    video_file = os.path.join(OUTPUT_DIR, "real_movie.avi")

    # 1. Generate real audio (~26 MB, 150 seconds stereo chord)
    generate_real_audio(audio_file, duration_sec=150)

    # 2. Generate real image (~51.8 MB, 4800x3600 pixel 24-bit RGB)
    generate_real_image(image_file, width=4800, height=3600)

    # 3. Generate real video (~276 MB, 640x480 uncompressed 10 seconds @ 30 FPS)
    generate_real_video(video_file, width=640, height=480, fps=30, num_frames=300)

    targets = [
        ("Audio", audio_file, ".wav"),
        ("Image", image_file, ".bmp"),
        ("Video", video_file, ".avi"),
    ]

    print("\n" + "=" * 80)
    print("ENCRYPTING & DECRYPTING WITH VAULT V2 (SCRYPT + AES-256-CTR + HMAC)")
    print("=" * 80)

    for label, src_path, ext in targets:
        vault_path = src_path + ".vault"
        dec_path = os.path.join(OUTPUT_DIR, f"decrypted_{label.lower()}{ext}")

        print(f"\nProcessing {label}: {os.path.basename(src_path)} ({os.path.getsize(src_path)/(1024*1024):.1f} MB)")

        orig_hash = compute_sha256(src_path)

        # Encrypt
        t0 = time.perf_counter()
        vault.encrypt_file(src_path, vault_path, PW, force=True, kdf="scrypt")
        te = time.perf_counter() - t0
        print(f"  -> Encrypted -> {os.path.basename(vault_path)} in {te:.2f}s")

        # Decrypt
        t1 = time.perf_counter()
        vault.decrypt_file(vault_path, dec_path, PW, force=True)
        td = time.perf_counter() - t1
        print(f"  -> Decrypted -> {os.path.basename(dec_path)} in {td:.2f}s")

        dec_hash = compute_sha256(dec_path)
        assert orig_hash == dec_hash, f"Hash mismatch for {label}!"
        print(f"  -> SHA-256 Match: {orig_hash[:16]}... == {dec_hash[:16]}... [100% BIT-FOR-BIT LOSSLESS]")

        # =========================================================================
        # NOTE: NO DELETIONS / NO CLEANUP!
        # Files are left permanently on disk for manual viewing and playback:
        # - os.remove(src_path)      <-- DISABLED / COMMENTED OUT
        # - os.remove(vault_path)    <-- DISABLED / COMMENTED OUT
        # - os.remove(dec_path)      <-- DISABLED / COMMENTED OUT
        # =========================================================================

    print("\n" + "=" * 80)
    print("SUCCESS! ALL FILES ARE PRESERVED ON DISK.")
    print(f"Directory: {OUTPUT_DIR}")
    print("You can now open Windows Explorer and double-click:")
    print("  1. real_soundtrack.wav & decrypted_audio.wav   (plays in Media Player/VLC)")
    print("  2. real_graphic.bmp & decrypted_image.bmp       (opens in Windows Photos/Paint)")
    print("  3. real_movie.avi & decrypted_video.avi         (plays in Media Player/VLC)")
    print("=" * 80)

if __name__ == "__main__":
    main()

