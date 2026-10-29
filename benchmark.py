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
    with tempfile.TemporaryDirectory(dir=".") as d:
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