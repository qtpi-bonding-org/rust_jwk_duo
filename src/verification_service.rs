//! Port of dart_jwk_duo lib/src/verification_service.dart.
use crate::error::{state, Result};
use crate::interfaces::KeyPair;
use crate::{CryptoService, EncryptionKeyPair, KeyDuo, KeyDuoSerializer, SigningKeyPair, SigningPublicKeyHex, SymmetricKey};

pub struct VerificationService;

impl VerificationService {
    pub fn verify_signature_with_public_key_sec1_hex(public_key: &SigningPublicKeyHex, signature: &[u8], data: &[u8]) -> Result<bool> {
        Ok(SigningKeyPair::import_public_key_sec1_hex(public_key)?.verify_bytes(signature, data))
    }
    pub fn verify_key_duo(duo: &KeyDuo) -> Result<bool> {
        if !Self::verify_signing_key_pair(duo.signing_key_pair())? { return Ok(false); }
        Self::verify_encryption_key_pair(duo.encryption_key_pair())
    }
    pub fn verify_signing_key_pair(kp: &SigningKeyPair) -> Result<bool> {
        if !kp.has_private_key() { return Err(state("Cannot verify: public-only key pair")); }
        let msg = b"dart-jwk-duo-verify";
        Ok(kp.sign_bytes(msg).map(|s| kp.verify_bytes(&s, msg)).unwrap_or(false))
    }
    pub fn verify_encryption_key_pair(kp: &EncryptionKeyPair) -> Result<bool> {
        if !kp.has_private_key() { return Err(state("Cannot verify: public-only key pair")); }
        let msg = b"dart-jwk-duo-verify-enc";
        Ok(CryptoService::encrypt(msg, kp, b"", b"").and_then(|c| CryptoService::decrypt(&c, kp, b"", b"")).map(|d| d == msg).unwrap_or(false))
    }
    pub fn verify_symmetric_key(key: &SymmetricKey) -> bool {
        let msg = b"verify-symmetric-key";
        CryptoService::encrypt_symmetric(msg, key, b"").and_then(|c| CryptoService::decrypt_symmetric(&c, key, b"")).map(|d| d == msg).unwrap_or(false)
    }
    pub fn verify_key_duo_jwk(json: &str) -> Result<KeyDuo> {
        let duo = KeyDuoSerializer::import_key_duo_jwk(json)?;
        if !Self::verify_key_duo(&duo)? { return Err(state("Key verification failed: cryptographic roundtrip test failed")); }
        Ok(duo)
    }
}

#[cfg(test)]
mod tests {
    use crate::*;
    #[test] fn generation_produces_distinct_working_pairs() {
        let d = GenerationService::generate_key_duo();
        assert!(VerificationService::verify_key_duo(&d).unwrap());
        assert!(VerificationService::verify_symmetric_key(&GenerationService::generate_symmetric_key()));
    }
    #[test] fn verify_via_sec1_hex_accepts_genuine_rejects_tampered_and_errors_on_malformed_key() {
        let d = GenerationService::generate_key_duo(); let sig = d.signing_key_pair().sign_bytes(b"m").unwrap();
        let hex = d.signing_key_pair().typed_public_hex();
        assert!(VerificationService::verify_signature_with_public_key_sec1_hex(&hex, &sig, b"m").unwrap());
        assert!(!VerificationService::verify_signature_with_public_key_sec1_hex(&hex, &sig, b"x").unwrap());
        assert!(SigningPublicKeyHex::new("04").is_err());
    }
    #[test] fn verify_key_duo_jwk_round_trips_and_public_only_is_a_state_error() {
        let d = GenerationService::generate_key_duo(); let j = KeyDuoSerializer::export_key_duo_jwk(&d).unwrap();
        assert!(VerificationService::verify_key_duo_jwk(&j).is_ok());
        let p = KeyDuoSerializer::import_public_key_duo_jwk(&j).unwrap();
        assert!(matches!(VerificationService::verify_key_duo(&p), Err(Error::State(_))));
    }
}
