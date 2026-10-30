# V3.1 Latency Evaluation — Header-MAC + Merkle-tree trailer patches

**Source:** unstaged changes in `vault.py` (+215 lines) and `test_vault.py` (+139 lines).  
**Method:** compared working tree (V3.1, patched) against the staged pre-patch V3 (`git show :vault.py`) on identical sizes/KDF. No project files were modified.

## Test suite
- Pre-patch V3: 46 tests (`res_v3.md`).
- V3.1 (current working tree): **54 passed** (`python -m pytest -q`), including 8 new tests:
  header-MAC ×3, Merkle ×2, Merkle helper ×3.

## Format delta (per file)
| Field | Bytes |
|---|---|
| Header-MAC tag | +32 |
| Merkle trailer (root + root HMAC) | +64 |
| **Total** | **+96 B** |

## KDF context (dominates small files)
| KDF | Time |
|---|---|
| scrypt N=65536 r=8 p=1 | ~247 ms |
| PBKDF2 600k iterations | ~806 ms |

So for files ≲ 10 MB, KDF cost dwarfs the added integrity work and latency is effectively unchanged.

## End-to-end latency (CPU time, min of 5 interleaved reps, scrypt default)
| Size (MB) | enc old (s) | enc V3.1 (s) | enc delta | dec old (s) | dec V3.1 (s) | dec delta |
|---|---|---|---|---|---|---|
| 25 | 0.250 | 0.328 | +31% | 0.266 | 0.281 | +6% |
| 100 | 0.484 | 0.562 | +16% | 0.406 | 0.500 | +23% |
| 200 | 0.688 | 0.844 | +23% | 0.578 | 0.672 | +16% |

## Isolated cost of added primitives
| Operation | 100 MB payload |
|---|---|
| SHA-256 hash every chunk + Merkle tree build | ~74 ms |
| Header-MAC (one HMAC-SHA256 over 50-byte header) | ~0.005 ms |

## Memory regression (real cost beyond latency)
Decrypt now buffers the entire plaintext in RAM before writing:
- Pre-patch V3 peak Python heap, 100 MB decrypt: ~5 MB
- V3.1 peak Python heap, 100 MB decrypt: ~102 MB (~1× file size)

## Verdict
**Latency increased modestly, not catastrophically.** The Header-MAC and Merkle trailer add a fixed ~96 B/file and roughly +74 ms of hashing per 100 MB (~+16% to +23% end-to-end at 100–200 MB). For small files the scrypt/PBKDF2 KDF dwarfs this, so latency is unchanged.

The bigger regression is **memory**: V3 decrypt buffers the whole plaintext before the Merkle root can be verified, costing ~1× file size in RAM, breaking the constant-memory / true single-pass streaming claim. That memory cost — not the CPU delta — is the dominant impact on large files.
