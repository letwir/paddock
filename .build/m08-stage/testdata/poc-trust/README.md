# PoC test-only Ed25519 vector

**TEST ONLY — NOT A PRODUCTION TRUST ROOT.** These files contain the public half and a published RFC 8032 test vector only. They are deterministic test data, not operational key material, a trust-anchor provisioning method, or authorization to trust any signer.

The public key and signature are RFC 8032, Section 7.1, Test 1 (empty message). `ed25519-public.hex` contains only the 32-byte public key in lowercase hexadecimal; `vector.json` carries the test message and expected signature in hex. No private key bytes are included or needed to verify this vector.

This fixture does not define an application signing algorithm, canonicalization, key custody, key ceremony, expiry, revocation, rotation, or approval quorum. Production algorithm/custody and the operational key lifecycle remain OPEN under O-002 (`PDK-M06-S08`). Never copy this fixture into production configuration or treat passing its test as production trust evidence.
