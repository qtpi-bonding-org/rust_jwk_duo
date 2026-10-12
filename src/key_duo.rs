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
