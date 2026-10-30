KDF cost comparison — papers 6, 7, 8
Build PBKDF2, scrypt, and Argon2id as selectable KDFs. Run a small password dictionary against each, measure guesses per second and memory used, on the same machine. Show scrypt and Argon2id cost far more per guess than PBKDF2.

Malicious-file and tampering test suite — papers 3, 4
Recreate the attack types from these two papers against your own vault format: file injection, header tampering, ciphertext tampering, version/parameter downgrade. Confirm every one is rejected by your HMAC check before any output is written.

Key-commitment comparison (GCM vs your HMAC design) — papers 1, 2
Build a second stripped-down version using AES-GCM. Construct a ciphertext that decrypts under two different passwords (following Len et al.’s method). Try the same construction against your HMAC-based design and show it fails.


1	Flexible Password-Based Encryption (Bellare, Shea)	CT-RSA 2023	Closest match to your project; defines flexible PBE resisting partitioning oracle attacks
2	Partitioning Oracle Attacks (Len, Grubbs, Ristenpart)	USENIX Security 2021	Defines the attack your MAC design defends against
3	MEGA: Malleable Encryption Goes Awry (Backendal, Haller, Paterson)	IEEE S&P 2023	Real-world failure case for missing integrity checks
4	End-to-End Encrypted Cloud Storage in the Wild (Hofmann, Truong)	ACM CCS 2024	Real-world failure case, four of five providers broken
5	Zero Knowledge (About) Encryption (Scarlata et al.)	USENIX Security 2026	Most recent, shows even major password managers fail this
6	Evaluating Argon2 Adoption and Effectiveness	2025	Real measured cracking costs under different KDF settings
7	Scrypt is Maximally Memory-Hard (Alwen et al.)	Eurocrypt 2017	Foundational proof behind your scrypt option
8	Argon2 (Biryukov, Dinu, Khovratovich)	Euro S&P 2016	Foundational spec behind your Argon2id option, now RFC 9106
9	Bellare and Namprempre	Asiacrypt 2000	Proves Encrypt-then-MAC is the safe composition, your core design choice
10	Bellare, Ristenpart, Tessaro	CRYPTO 2012	Proves salting amplifies security, backs your per-file salt