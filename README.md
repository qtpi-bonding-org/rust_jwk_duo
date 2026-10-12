# rust_jwk_duo

Rust port of `dart_jwk_duo` 2.0.0. Module layout and names follow the Dart
library (snake_case for Rust). One signing key pair (ECDSA P-256) plus one
encryption key pair (HPKE, `DhP256HkdfSha256` / `HkdfSha256` / `AesGcm256`),
exported as a two-key JWK Set.

Differences from 2.x, all deliberate:

- Encryption is HPKE (single shot, base mode). Blob: `0x01 || enc(65) || ct || tag`.
  JWK `alg` for the encryption key is `HPKE-7`. 2.x ciphertexts and 2.x JWK Sets
  carrying `ECDH-ES+A256KW` are rejected.
- Everything is synchronous (no `Future`).
- Signatures are 64-byte P1363 `r || s`.
- Errors: `Error::Format`, `Error::State`, `Error::Argument` map 1:1 to Dart's
  `FormatException`, `StateError`, `ArgumentError`.
- No WebCrypto. Platforms: macOS, Linux, iOS, Android.

## Parity table (dart_jwk_duo 2.0.0 to rust_jwk_duo)

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

## Development

`cargo test` and `cargo clippy --all-targets -- -D warnings`.
