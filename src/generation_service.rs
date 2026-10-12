//! Port of dart_jwk_duo lib/src/generation_service.dart.
use crate::{EncryptionKeyPair, KeyDuo, SigningKeyPair, SymmetricKey};

pub struct GenerationService;

impl GenerationService {
    pub fn generate_key_duo() -> KeyDuo {
        KeyDuo::new(SigningKeyPair::generate(), EncryptionKeyPair::generate()).expect("independent random keys differ")
    }
    pub fn generate_symmetric_key() -> SymmetricKey { SymmetricKey::generate() }
}
