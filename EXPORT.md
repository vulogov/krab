Krab is publicly available encryption source code.

Classification:  ECCN 5D002, released from the EAR under 15 CFR 734.7
                 and 742.15(b)(1) as publicly available source code.

Non-standard cryptography (15 CFR 772.1): none.
  Confidentiality:  ChaCha20-Poly1305 (RFC 8439), X25519 (RFC 7748),
                    HPKE (RFC 9180), HKDF (RFC 5869), ML-KEM (FIPS 203)
  Authentication:   Ed25519 (RFC 8032)
  KDF:              Argon2id (RFC 9106)
  Hashing:          BLAKE3 — published specification; used for content
                    addressing and identity, not confidentiality
  Transport:        Noise Protocol Framework rev 34 — published specification
  Protocol:         KRAB RFC 0-8, published at https://github.com/vulogov/krab

No cryptographic functionality in this project is proprietary or unpublished.
