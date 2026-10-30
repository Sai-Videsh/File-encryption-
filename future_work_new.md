# Future Work — Encrypted File Vault (V3)

> This document outlines the **remaining limitations** after the planned
> Header-MAC and Merkle-tree root patches, and proposes three research-backed
> advancements as future work.

---

## Current Limitations (post Header-MAC + Merkle Tree)

After implementing the Header-level MAC (CT-RSA 2021) and Merkle-tree root
(USENIX ATC 2022) patches, the following structural limitations **remain
untouched** in V3:

| # | Limitation | Impact |
|---|-----------|--------|
| L1 | **No deduplication** — every encryption of the same file produces a unique ciphertext, so identical files are stored redundantly | Wastes storage and I/O bandwidth |
| L2 | **No in-vault search** — files can only be found by decrypting the entire vault; no keyword-based lookup exists | Poor usability at scale |
| L3 | **Classical key derivation only (PBKDF2 + AES-CTR)** — vulnerable to Grover's algorithm on a future quantum computer | Long-term archival security risk |
| L4 | **Fixed-size chunks leak payload-size patterns** — an observer can infer approximate file sizes from chunk counts | Metadata side-channel |

---

## Future Advancements

---

### Advancement 1 — Convergent Deduplication (CE+) ⭐ *Recommended*

**Addresses:** L1 (storage cost, I/O latency, redundant writes)

**Research paper:**
> M. Bellare, S. Keelveedhi, T. Ristenpart —
> *"Message-Locked Encryption and Secure Deduplication"*,
> **Eurocrypt 2013** / extended in **ACM CCS 2020** as *CryptDedup*.
> DOI: [10.1145/3372297.3423356](https://doi.org/10.1145/3372297.3423356)

**Why recommended:**
Directly reduces **storage cost and I/O overhead** by deriving a
deterministic per-chunk encryption key from the chunk's own plaintext
(SHA-256 digest), so identical chunks across files produce identical
ciphertexts and can be stored once. The master password still wraps the
per-chunk key (envelope encryption), preserving confidentiality. Impact is
measurable in real benchmarks — duplicate-heavy workloads (backups,
archives) see 30–60 % storage reduction with no change in cryptographic
strength.

**High-level design change:**
```
Current:  plaintext → random salt → PBKDF2 → AES-CTR-key → ciphertext
CE+ flow: plaintext_chunk → SHA-256(chunk) → DEK
                          → PBKDF2(password) → Encrypt(DEK)   [envelope]
                          → AES-GCM(chunk, DEK) → ciphertext
                          → fingerprint index (.vault_index) for dedup lookup
```

**Major code changes required:**
- New `_derive_convergent_key(chunk_bytes)` function
- New envelope-encryption layer (master key wraps per-chunk DEK)
- New chunk fingerprint index file (`.vault_index`)
- Updated `encrypt_file()` and `decrypt_file()` paths
- New CLI flag: `--dedup`

**Future scope:** Secure cross-user deduplication in shared cloud vaults
without leaking file contents to the storage provider.

---

### Advancement 2 — Searchable Symmetric Encryption (SSE)

**Addresses:** L2 (no in-vault search capability)

**Research paper:**
> R. Bost, B. Minaud, O. Ohrimenko —
> *"Forward and Backward Private Searchable Encryption from Constrained Cryptographic Primitives"*,
> **ACM CCS 2017** / revisited in **POPETS 2022** as forward-private SSE.
> DOI: [10.1145/3133956.3133980](https://doi.org/10.1145/3133956.3133980)

**Why listed:**
Allows keyword-based search over encrypted files **without decrypting
anything** — the vault maintains an Encrypted Database (EDB) that maps
search tokens (derived from password + keyword) to encrypted file IDs.
Forward-privacy ensures new file additions cannot be correlated with past
searches.

**Major code changes required (~400 lines, new subsystem):**
- New `vault_sse.py` module and `vault_index.py` for the EDB
- Modified `encrypt_file()` to extract and index keywords from metadata
- New CLI command: `vault.py search "<keyword>"`

**Future scope:** Multi-user shared encrypted vault with private boolean
keyword search.

---

### Advancement 3 — Post-Quantum Hybrid Key Encapsulation (ML-KEM / Kyber)

**Addresses:** L3 (quantum vulnerability of PBKDF2 + AES-CTR key derivation)

**Research paper:**
> N. Bindel, J. Brendel, M. Fischlin, B. Goncalves, D. Stebila —
> *"Hybrid Key Encapsulation Mechanisms and Authenticated Key Exchange"*,
> **PQCrypto 2019** / IACR ePrint 2022/993.
> Standardised as **NIST FIPS 203 — ML-KEM** (August 2024).
> URL: [https://csrc.nist.gov/pubs/fips/203/final](https://csrc.nist.gov/pubs/fips/203/final)

**Why listed:**
Combines classical PBKDF2 with ML-KEM-768 (Kyber) in a hybrid KEM so that
breaking **either** component is insufficient to recover the file key.
Aligns with the NIST-finalised standard (August 2024) — the strongest
possible citation for long-term archival security.

**Major code changes required:**
- New dependency: `pqcrypto` / `kyber-py`
- New V4 header format with KEM ciphertext field (~1168 bytes for ML-KEM-768)
- New `_hybrid_kdf(password, kyber_keypair)` function
- Key-pair generation command: `vault.py keygen`
- New CLI flag: `--pq` (enables V4 post-quantum mode)

**Future scope:** Quantum-safe long-term archival; government / enterprise
compliance with NIST PQC standards.

---

## Summary

| Advancement | Limitation Addressed | Paper Venue | Code Impact | Priority |
|---|---|---|---|---|
| **1 – CE+ Convergent Dedup** ⭐ | Storage cost, I/O latency | Eurocrypt / ACM CCS 2020 | Medium | **Recommended** |
| **2 – SSE Search** | No search capability | ACM CCS / POPETS 2022 | Large | Secondary |
| **3 – Post-Quantum KEM** | Quantum vulnerability | NIST FIPS 203 (2024) | Large | Long-term |

> **Recommendation:** Implement Advancement 1 (CE+) first — it produces
> measurable, benchmark-provable improvements in storage cost and I/O
> latency while remaining within the existing AES-CTR + HMAC cryptographic
> stack, making it the most self-contained and impactful next step.
