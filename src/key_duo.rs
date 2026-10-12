//! Port of dart_jwk_duo lib/src/key_duo.dart. Fixes bug 2 (equal halves).
use crate::error::{argument, Result};
use crate::interfaces::KeyPair;
use crate::{EncryptionKeyPair, PublicKeyDuo, SigningKeyPair};

#[derive(Debug)]
pub struct KeyDuo { signing: SigningKeyPair, encryption: EncryptionKeyPair }

impl KeyDuo {
    pub fn new(signing: SigningKeyPair, encryption: EncryptionKeyPair) -> Result<Self> {
        if signing.export_public_key_raw() == encryption.export_public_key_raw() {
            return Err(argument("Signing and encryption keys are identical; a key duo needs two different key pairs"));
        }
        Ok(Self { signing, encryption })
    }
    pub fn into_parts(self) -> (SigningKeyPair, EncryptionKeyPair) { (self.signing, self.encryption) }
    pub fn signing_key_pair(&self) -> &SigningKeyPair { &self.signing }
    pub fn encryption_key_pair(&self) -> &EncryptionKeyPair { &self.encryption }
    pub fn export_public_key_duo(&self) -> PublicKeyDuo {
        PublicKeyDuo::new(self.signing.typed_public_hex(), self.encryption.typed_public_hex()).expect("halves differ (checked in new)")
    }
}
#[cfg(test)]
mod tests {
    use super::*; use crate::interfaces::KeyPair; use crate::*;
    #[test] fn rejects_identical_halves() { // bug 2: key_duo.dart:25
        let s = SigningKeyPair::generate();
        let e = EncryptionKeyPair::import_public_key_raw(&s.export_public_key_raw()).unwrap();
        assert!(matches!(KeyDuo::new(s, e), Err(Error::Argument(_))));
    }
    #[test] fn halves_differ_and_two_duos_share_nothing() {
        let a = KeyDuo::new(SigningKeyPair::generate(), EncryptionKeyPair::generate()).unwrap();
        let b = KeyDuo::new(SigningKeyPair::generate(), EncryptionKeyPair::generate()).unwrap();
        let pa = a.export_public_key_duo(); let pb = b.export_public_key_duo();
        assert_ne!(pa.signing.value(), pa.encryption.value());
        for x in [pa.signing.value(), pa.encryption.value()] { assert!(x != pb.signing.value() && x != pb.encryption.value()); }
    }
    #[test] fn a_signing_key_imports_as_an_encryption_key_no_type_sniffing() {
        let s = SigningKeyPair::generate();
        assert!(EncryptionKeyPair::import_public_key_raw(&s.export_public_key_raw()).is_ok());
    }
}

impl KeyDuo {
    pub fn encrypt(&self, data: &[u8], info: &[u8], aad: &[u8]) -> Result<Vec<u8>> { crate::CryptoService::encrypt(data, &self.encryption, info, aad) }
    pub fn decrypt(&self, data: &[u8], info: &[u8], aad: &[u8]) -> Result<Vec<u8>> { crate::CryptoService::decrypt(data, &self.encryption, info, aad) }
    pub fn sign(&self, data: &[u8]) -> Result<[u8; 64]> { self.signing.sign_bytes(data) }
    pub fn verify_signature(&self, data: &[u8], sig: &[u8]) -> bool { self.signing.verify_bytes(sig, data) }
    pub fn encrypt_string(&self, s: &str, info: &[u8], aad: &[u8]) -> Result<String> { crate::CryptoService::encrypt_string(s, &self.encryption, info, aad) }
    pub fn decrypt_string(&self, b64: &str, info: &[u8], aad: &[u8]) -> Result<String> { crate::CryptoService::decrypt_string(b64, &self.encryption, info, aad) }
    pub fn sign_string(&self, s: &str) -> Result<String> { crate::CryptoService::sign_string(s, &self.signing) }
    pub fn verify_signature_string(&self, s: &str, sig_hex: &str) -> Result<bool> { crate::CryptoService::verify_signature_string(s, sig_hex, &self.signing) }
}
#[cfg(test)]
mod convenience_tests {
    use crate::*;
    #[test] fn duo_convenience_methods_round_trip() {
        let d = KeyDuo::new(SigningKeyPair::generate(), EncryptionKeyPair::generate()).unwrap();
        assert_eq!(d.decrypt(&d.encrypt(b"x", b"i", b"a").unwrap(), b"i", b"a").unwrap(), b"x");
        assert!(d.decrypt(&d.encrypt(b"x", b"i", b"a").unwrap(), b"j", b"a").is_err());
        assert!(d.verify_signature(b"m", &d.sign(b"m").unwrap()));
        assert_eq!(d.decrypt_string(&d.encrypt_string("s", b"", b"").unwrap(), b"", b"").unwrap(), "s");
        assert!(d.verify_signature_string("m", &d.sign_string("m").unwrap()).unwrap());
    }
}
