# rust_jwk_duo

Rust port of `dart_jwk_duo` 2.0.0. Module layout and names follow the Dart
library (snake_case for Rust). One signing key pair (ECDSA P-256) plus one
encryption key pair (HPKE, `DhP256HkdfSha256` / `HkdfSha256` / `AesGcm256`),
exported as a two-key JWK Set.

Differences from 2.x, all deliberate:

- Encryption is HPKE (RFC 9180, single shot, base mode). Blob: `0x01 || enc(65) || ct || tag`.
  JWK `alg` for the encryption key is `HPKE-7`. 2.x ciphertexts and 2.x JWK Sets
  carrying `ECDH-ES+A256KW` are rejected.
- **HPKE, not JWE.** The ciphertext is this library's own blob (version byte,
  encapsulated key, AEAD output). It is not a JWE compact or JSON serialization
  and no JOSE library will open it. Only the key's `alg` name (`HPKE-7`, from
  draft-ietf-jose-hpke-encrypt) is shared with JOSE.
- HPKE `info` is `rust_jwk_duo/hpke/v1\0` followed by the caller's `info`; `aad` is passed through.
- Everything is synchronous (no `Future`).
- Signatures are 64-byte P1363 `r || s`.
- Errors: `Error::Format`, `Error::State`, `Error::Argument` map 1:1 to Dart's
  `FormatException`, `StateError`, `ArgumentError`.
- Symmetric keys are 256-bit only (2.x accepted 128-bit).
- `CryptoService::decrypt_string` decodes strict padded standard base64 (`base64ct`).
- No WebCrypto. Platforms: macOS, Linux, iOS, Android (binding verified on Linux/amd64 in Docker and on an x86_64 Android emulator; see the `dart_jwk_duo` README).

Bugs found in 2.x and fixed in the port: `kid` is checked against the thumbprint; a duo
with one key in both halves is rejected; JWK members must be canonical unpadded
base64url; non-string or non-object JSON in any position is a format error, not a type
error or panic; 128-bit symmetric keys are rejected; the private `d` is checked against
`x`/`y`; `ExportedJwk` validation and `validate_no_private_key_material` cope with
malformed input; the public-key extractors parse inside their error handling.

## Parity table (dart_jwk_duo 2.0.0 to rust_jwk_duo)

Dart 3.0 keeps the 2.x name for every symbol not marked removed (with `Future` returns and
`dispose()`); the 3.0 column of the table is in the `dart_jwk_duo` README.

### Constants (`constants`)

| Dart | Rust |
|---|---|
| `JwkKeyType.ec` | `constants::jwk_key_type::EC` |
| `JwkAlgorithm.es256` | `constants::jwk_algorithm::ES256` |
| `JwkAlgorithm.ecdhEs256` | removed: replaced by `jwk_algorithm::HPKE7` (`"HPKE-7"`) |
| `JwkUse.signature`, `.encryption` | `constants::jwk_use::{SIGNATURE, ENCRYPTION}` |
| `JwkCurve.p256` | `constants::jwk_curve::P256` |
| `CryptoSizes.aesGcmIvLength`, `aesGcmTagLength` | `constants::crypto_sizes::{AES_GCM_IV_LENGTH, AES_GCM_TAG_LENGTH}` |
| `CryptoSizes.sec1UncompressedTag`, `ecP256Sec1PublicKeyLength`, `ecP256Sec1PublicKeyHexLength`, `ecdsaP256SignatureLength` | `constants::crypto_sizes::{SEC1_UNCOMPRESSED_TAG, EC_P256_SEC1_PUBLIC_KEY_LENGTH, EC_P256_SEC1_PUBLIC_KEY_HEX_LENGTH, ECDSA_P256_SIGNATURE_LENGTH}` |
| `CryptoSizes.hkdfSaltLength`, `hybridHeaderLength` | removed: old recipe (HPKE has no salt or IV header) |
| `DefaultKeyIds` | removed: no callers |
| `KeyIdFormatting` | removed: no callers |
| (none) | new: `jwk_key_type::OCT`, `jwk_algorithm::{HPKE7, A256GCM}`, `crypto_sizes::{AES_256_KEY_LENGTH, EC_P256_COORDINATE_LENGTH}`, `FORMAT_VERSION`, `constants::hpke::*` |

### Encoding

| Dart | Rust |
|---|---|
| `HexCodec.encode` / `decode(hex, expectedLength:)` | `HexCodec::encode` / `decode(hex, expected_len)` |
| `Sec1PublicKey.validateRaw` / `decodeHex` / `encodeHex` | `Sec1PublicKey::validate_raw` / `decode_hex` / `encode_hex` |
| (none) | new: `Sec1PublicKey::import_p256` / `export_p256` |
| `SigningPublicKeyHex(hex)`, `.value` | `SigningPublicKeyHex::new(&str)`, `.value()` |
| `EncryptionPublicKeyHex(hex)`, `.value` | `EncryptionPublicKeyHex::new(&str)`, `.value()` |
| `PublicKeyDuo`, `signingJsonKey`, `encryptionJsonKey`, `toJson`, `fromJson` | `PublicKeyDuo`, `SIGNING_JSON_KEY`, `ENCRYPTION_JSON_KEY`, `to_json`, `from_json` |

### Interfaces and DTOs

| Dart | Rust |
|---|---|
| `IKeyPair` | `KeyPair` trait: `has_private_key`, `export_private_key`, `export_public_key`, `export_public_key_raw`, `export_public_key_sec1_hex`, `calculate_key_id` |
| `IKeyPair.privateKey`, `.publicKey` (WebCrypto-typed getters) | removed: no WebCrypto |
| `IKeyDuo` | removed: `KeyDuo` is the only implementation (`signing_key_pair()`, `encryption_key_pair()`) |
| `ExportedJwk` (`keyId`, `alg`, `use`, `toJson`, `toPublicOnly`) | `ExportedJwk` (`key_id`, `alg`, `use_`, `to_json`, `to_public_only`) |
| `calculateJwkThumbprint` | `calculate_jwk_thumbprint` |

### Key pairs and containers

| Dart | Rust |
|---|---|
| `SigningKeyPair(privateKey:, publicKey:)`, `.publicOnly(...)` | removed: WebCrypto-typed constructors. Use `SigningKeyPair::generate`, `KeyDuoSerializer`, or the public-only imports below |
| `SigningKeyPair.importPublicKeyRaw` / `importPublicKeySec1Hex` | `SigningKeyPair::import_public_key_raw` / `import_public_key_sec1_hex` |
| `signBytes` / `verifyBytes` | `sign_bytes` / `verify_bytes` (verify returns `false` on a malformed signature) |
| `exportPublicKeyRaw` / `exportPublicKeySec1Hex` (typed) | `KeyPair::export_public_key_raw` / `typed_public_hex` (untyped: `export_public_key_sec1_hex`) |
| `exportPrivateKey` / `exportPublicKey` / `calculateKeyId` | `KeyPair::export_private_key` / `export_public_key` / `calculate_key_id` |
| (none) | new: `SigningKeyPair::signature_from_der` / `signature_to_der` |
| `EncryptionKeyPair(...)`, `.publicOnly(...)` | removed: WebCrypto-typed constructors. Use `EncryptionKeyPair::generate`, `KeyDuoSerializer`, or the public-only imports below |
| `EncryptionKeyPair.importPublicKeyRaw` / `importPublicKeySec1Hex` | `EncryptionKeyPair::import_public_key_raw` / `import_public_key_sec1_hex` |
| `EncryptionKeyPair` export members (as for signing) | `KeyPair` trait, `typed_public_hex` |
| `KeyDuo(signing:, encryption:)` | `KeyDuo::new(signing, encryption)` (fails if both halves share a public key) |
| `KeyDuo.signingKeyPair`, `.encryptionKeyPair` | `signing_key_pair()`, `encryption_key_pair()` |
| `KeyDuo.exportPublicKeyDuo` | `export_public_key_duo` |
| `KeyDuo.encrypt` / `decrypt` / `sign` / `verifySignature(data, sig)` | `encrypt(data, info, aad)` / `decrypt(data, info, aad)` / `sign` / `verify_signature(data, sig)` |
| `KeyDuo.encryptString` / `decryptString` / `signString` / `verifySignatureString` | `encrypt_string` / `decrypt_string` / `sign_string` / `verify_signature_string` |
| `SymmetricKey.fromJwk` / `toJwk` | `SymmetricKey::from_jwk` / `to_jwk` (256-bit keys only) |
| `SymmetricKey.fromAesKey`, `.internal` | removed: WebCrypto-typed |

### Services

| Dart | Rust |
|---|---|
| `GenerationService.generateKeyDuo` / `generateSymmetricKey` | `GenerationService::generate_key_duo` / `generate_symmetric_key` |
| `CryptoService.encrypt` / `decrypt` | `CryptoService::encrypt(data, recipient, info, aad)` / `decrypt(...)` (HPKE) |
| `CryptoService.sign` / `verifySignature` | `CryptoService::sign` / `verify_signature` |
| `CryptoService.encryptSymmetric` / `decryptSymmetric` | `CryptoService::encrypt_symmetric(data, key, aad)` / `decrypt_symmetric` |
| `CryptoService.encryptString` / `decryptString` / `signString` / `verifySignatureString` | `encrypt_string` / `decrypt_string` / `sign_string` / `verify_signature_string` |
| `ValidationService.validateKeyDuoJwkStructure` | `ValidationService::validate_key_duo_jwk_structure` |
| `ValidationService.validateEcdsaKey` / `validateEcdhKey` | `validate_signing_key` / `validate_encryption_key` |
| `ValidationService.validateSymmetricKeyJwk` / `validateSymmetricKeyJwkString` | `validate_symmetric_key_jwk` / `validate_symmetric_key_jwk_string` |
| `ValidationService.extractPublicKeyFields` / `extractPublicKeySet` | `extract_public_key_fields` / `extract_public_key_set` |
| `ValidationService.validateNoPrivateKeyMaterial` / `validateKeyDuoJwk` | `validate_no_private_key_material` / `validate_key_duo_jwk` |
| `VerificationService.verifySignatureWithPublicKeySec1Hex` | `verify_signature_with_public_key_sec1_hex` |
| `VerificationService.verifyKeyDuo` / `verifySigningKeyPair` / `verifyEncryptionKeyPair` / `verifySymmetricKey` / `verifyKeyDuoJwk` | `verify_key_duo` / `verify_signing_key_pair` / `verify_encryption_key_pair` / `verify_symmetric_key` / `verify_key_duo_jwk` |
| `IKeyDuoSerializer` | removed: `KeyDuoSerializer` is a unit struct with associated functions |
| `KeyDuoSerializer.exportKeyDuoJwk` / `exportPublicKeyDuoJwk` | `export_key_duo_jwk` / `export_public_key_duo_jwk` |
| `KeyDuoSerializer.importKeyDuoJwk` / `importPublicKeyDuoJwk` | `import_key_duo_jwk` / `import_public_key_duo_jwk` |
| `KeyDuoSerializer.extractSigningPublicKeySec1Hex` / `extractEncryptionPublicKeySec1Hex` / `extractPublicKeyDuo` | `extract_signing_public_key_sec1_hex` / `extract_encryption_public_key_sec1_hex` / `extract_public_key_duo` |
| `KeyDuoSerializer.verifyJwk` | removed: duplicate of `VerificationService::verify_key_duo_jwk` |

## Format version and conformance

`constants::FORMAT_VERSION` (currently 1) is the version of the conformance
vector format. Every vector file declares it and both runners assert it, so a
vector set that does not match the code fails loudly. The runner contract (ops,
inputs, expected results, error kinds) is in [conformance/README.md](conformance/README.md);
the Dart binding runs the same vectors.

The vectors are of two kinds, and only one is independent evidence of correctness:

- Independent: Wycheproof (ECDSA, ECDH, AES-GCM), the RFC 9180 test vector, the
  JOSE HPKE-7 Appendix A.13 key, and the `circl_*` blobs in `hpke_open.json`
  (generated by Cloudflare CIRCL through `conformance/tools/kat-gen`).
- Frozen Rust outputs, i.e. regression fixtures: the thumbprint keys, `jwk_set_valid`,
  `signature_verify` and `symmetric_open` fixtures were produced by this crate. They
  catch drift between Rust and Dart and between releases; they do not show the crate
  agrees with anyone else.

## Toolchain

Rust 1.85 or newer (`rust-version`; developed on 1.92). Nothing else is needed for the crate itself.
The Dart binding also needs the targets and tools listed in the `dart_jwk_duo` README.

## Linux

The binding built and passed its Dart suite on Linux/amd64 in Docker (`dart:3.11`, 2026-10-12), which compiles this crate there. The command (mounts both sibling repos, builds, runs the Dart suite) is in the
`dart_jwk_duo` README under "Linux"; to test only this crate:

```bash
docker run --rm -v "$PWD:/src" -w /src rust:1.92 cargo test
```

(this crate-only command has not been run).

## Platform loading

This crate is a plain Rust library with no loading logic. Loading the native build is the
binding's job; see "Platform loading" in the `dart_jwk_duo` README (iOS simulator and Android x86_64
emulator verified).

## Development

`cargo test` and `cargo clippy --all-targets -- -D warnings`.
