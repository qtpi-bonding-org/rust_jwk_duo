//! Port of dart_jwk_duo lib/src/constants.dart. Hybrid-layout constants
//! (HKDF salt, hybrid header) are gone with the old recipe; HPKE ones are new.

pub mod jwk_key_type { pub const EC: &str = "EC"; pub const OCT: &str = "oct"; }

pub mod jwk_algorithm {
    pub const ES256: &str = "ES256";
    /// JOSE HPKE (draft-ietf-jose-hpke-encrypt-22): DHKEM(P-256, HKDF-SHA256),
    /// HKDF-SHA256, AES-256-GCM. jwk_duo ciphertexts are NOT JWE: different
    /// `info`, no protected-header AAD.
    pub const HPKE7: &str = "HPKE-7";
    pub const A256GCM: &str = "A256GCM";
}

pub mod jwk_use { pub const SIGNATURE: &str = "sig"; pub const ENCRYPTION: &str = "enc"; }

pub mod jwk_curve { pub const P256: &str = "P-256"; }

pub mod crypto_sizes {
    pub const AES_GCM_IV_LENGTH: usize = 12;
    pub const AES_GCM_TAG_LENGTH: usize = 16;
    pub const AES_256_KEY_LENGTH: usize = 32;
    pub const SEC1_UNCOMPRESSED_TAG: u8 = 0x04;
    pub const EC_P256_SEC1_PUBLIC_KEY_LENGTH: usize = 65;
    pub const EC_P256_SEC1_PUBLIC_KEY_HEX_LENGTH: usize = EC_P256_SEC1_PUBLIC_KEY_LENGTH * 2;
    pub const ECDSA_P256_SIGNATURE_LENGTH: usize = 64;
    pub const EC_P256_COORDINATE_LENGTH: usize = 32;
}

/// Conformance vector format version. Every vector file must declare the
/// same value; the runners assert it (spec §4 freshness rule).
pub const FORMAT_VERSION: u32 = 1;

pub mod hpke {
    pub const VERSION_V1: u8 = 0x01;
    pub const INFO_PREFIX: &[u8] = b"rust_jwk_duo/hpke/v1\0";
    /// version byte + encapsulated key (SEC1 uncompressed P-256)
    pub const HEADER_LENGTH: usize = 1 + super::crypto_sizes::EC_P256_SEC1_PUBLIC_KEY_LENGTH;
    pub const MIN_BLOB_LENGTH: usize = HEADER_LENGTH + super::crypto_sizes::AES_GCM_TAG_LENGTH;
}

#[cfg(test)]
mod tests {
    use super::*;
    // Port of sec1_parity_test.dart "SEC1 constants: sizes are internally consistent".
    #[test]
    fn sizes_are_internally_consistent() {
        assert_eq!(crypto_sizes::EC_P256_SEC1_PUBLIC_KEY_LENGTH, 1 + 2 * crypto_sizes::EC_P256_COORDINATE_LENGTH);
        assert_eq!(crypto_sizes::EC_P256_SEC1_PUBLIC_KEY_HEX_LENGTH, 130);
        assert_eq!(hpke::MIN_BLOB_LENGTH, 1 + 65 + 16);
    }
}
