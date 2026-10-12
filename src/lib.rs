//! rust_jwk_duo: port of dart_jwk_duo (structure and names kept), with HPKE.
pub mod constants;
mod error;
pub use error::{Error, Result};
pub mod hex_codec; pub use hex_codec::HexCodec;
pub mod sec1_public_key; pub use sec1_public_key::Sec1PublicKey;
pub mod public_key_hex; pub use public_key_hex::*;
mod jwk;
pub mod jwk_thumbprint; pub use jwk_thumbprint::calculate_jwk_thumbprint;
pub mod exported_jwk; pub use exported_jwk::ExportedJwk;
pub mod interfaces; pub use interfaces::KeyPair;
pub mod signing_key_pair; pub use signing_key_pair::SigningKeyPair;
pub mod encryption_key_pair; pub use encryption_key_pair::EncryptionKeyPair;
pub mod key_duo; pub use key_duo::KeyDuo;
pub mod symmetric_key; pub use symmetric_key::SymmetricKey;
pub mod crypto_service; pub use crypto_service::CryptoService;
pub mod validation_service; pub use validation_service::ValidationService;
pub mod key_duo_serializer; pub use key_duo_serializer::KeyDuoSerializer;
pub mod generation_service; pub use generation_service::GenerationService;
pub mod verification_service; pub use verification_service::VerificationService;

// Test hooks for the external-vector runner; compiled only with the `test-hooks` feature,
// which this crate enables for its own tests through a dev-dependency on itself.
#[cfg(feature = "test-hooks")]
#[doc(hidden)]
pub fn __parse_ec_public_jwk(json: &str) -> Result<()> {
    match serde_json::from_str::<serde_json::Value>(json) {
        Ok(serde_json::Value::Object(m)) => jwk::parse_ec_public(&m).map(|_| ()),
        _ => Err(Error::Format("Invalid JSON format".into())),
    }
}
#[cfg(feature = "test-hooks")]
#[doc(hidden)]
pub fn __parse_ec_private_jwk(json: &str) -> Result<()> {
    match serde_json::from_str::<serde_json::Value>(json) {
        Ok(serde_json::Value::Object(m)) => jwk::parse_ec_private(&m).map(|_| ()),
        _ => Err(Error::Format("Invalid JSON format".into())),
    }
}
#[cfg(feature = "test-hooks")]
#[doc(hidden)]
pub fn __exported_jwk_check(alg: &str, use_: &str) -> Result<()> {
    let mut m = serde_json::Map::new();
    m.insert("kty".into(), constants::jwk_key_type::EC.into());
    ExportedJwk::new(m, String::new(), alg, use_).map(|_| ())
}
