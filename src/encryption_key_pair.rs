//! Port of dart_jwk_duo lib/src/encryption_key_pair.dart. The key pair is the
//! HPKE KEM key pair (DHKEM(P-256, HKDF-SHA256)).
use crate::constants::{jwk_algorithm, jwk_use};
use crate::error::{state, Result};
use crate::interfaces::KeyPair;
use crate::{calculate_jwk_thumbprint, jwk, EncryptionPublicKeyHex, ExportedJwk, Sec1PublicKey};
use hpke::{kem::DhP256HkdfSha256, Deserializable, Kem};

pub struct EncryptionKeyPair { private: Option<p256::SecretKey>, public: p256::PublicKey }

impl EncryptionKeyPair {
    pub fn generate() -> Self {
        use p256::elliptic_curve::Generate;
        let sk = p256::SecretKey::generate();
        let public = sk.public_key();
        Self { private: Some(sk), public }
    }
    pub fn import_public_key_raw(raw: &[u8]) -> Result<Self> { Ok(Self { private: None, public: Sec1PublicKey::import_p256(raw)? }) }
    pub fn import_public_key_sec1_hex(hex: &EncryptionPublicKeyHex) -> Result<Self> { Self::import_public_key_raw(&Sec1PublicKey::decode_hex(hex.value())?) }
    pub(crate) fn from_jwk_members(m: &serde_json::Map<String, serde_json::Value>, private: bool) -> Result<Self> {
        if private { let sk = jwk::parse_ec_private(m)?; let public = sk.public_key(); Ok(Self { private: Some(sk), public }) }
        else { Ok(Self { private: None, public: jwk::parse_ec_public(m)? }) }
    }
    pub fn typed_public_hex(&self) -> EncryptionPublicKeyHex { EncryptionPublicKeyHex::new(&self.export_public_key_sec1_hex()).expect("own key is valid SEC1") }
    pub(crate) fn hpke_public(&self) -> <DhP256HkdfSha256 as Kem>::PublicKey {
        <DhP256HkdfSha256 as Kem>::PublicKey::from_bytes(&self.export_public_key_raw()).expect("valid P-256 point")
    }
    pub(crate) fn hpke_private(&self) -> Result<<DhP256HkdfSha256 as Kem>::PrivateKey> {
        let sk = self.private.as_ref().ok_or_else(|| state("Cannot decrypt: public-only encryption key pair"))?;
        let bytes = zeroize::Zeroizing::new(sk.to_bytes());
        Ok(<DhP256HkdfSha256 as Kem>::PrivateKey::from_bytes(bytes.as_slice()).expect("valid scalar"))
    }
}

impl KeyPair for EncryptionKeyPair {
    fn has_private_key(&self) -> bool { self.private.is_some() }
    fn export_private_key(&self) -> Result<ExportedJwk> {
        let sk = self.private.as_ref().ok_or_else(|| state("Cannot export private key: This is a public-only key pair"))?;
        ExportedJwk::new(jwk::ec_private_members(sk), self.calculate_key_id()?, jwk_algorithm::HPKE7, jwk_use::ENCRYPTION)
    }
    fn export_public_key(&self) -> Result<ExportedJwk> {
        ExportedJwk::new(jwk::ec_public_members(&self.public), self.calculate_key_id()?, jwk_algorithm::HPKE7, jwk_use::ENCRYPTION)
    }
    fn export_public_key_raw(&self) -> [u8; 65] { Sec1PublicKey::export_p256(&self.public) }
    fn calculate_key_id(&self) -> Result<String> { calculate_jwk_thumbprint(&jwk::ec_public_members(&self.public)) }
}
impl std::fmt::Debug for EncryptionKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptionKeyPair").field("public", &self.export_public_key_sec1_hex()).field("has_private_key", &self.private.is_some()).finish()
    }
}
#[cfg(test)]
mod tests {
    use super::*; use crate::interfaces::KeyPair;
    #[test] fn export_metadata_is_hpke7_enc() {
        let kp = EncryptionKeyPair::generate(); let j = kp.export_private_key().unwrap().to_json();
        assert_eq!(j["alg"], "HPKE-7"); assert_eq!(j["use"], "enc"); assert_eq!(j["kid"], kp.calculate_key_id().unwrap().as_str());
    }
    #[test] fn sec1_round_trip_is_byte_identical() {
        let kp = EncryptionKeyPair::generate(); let hex = kp.export_public_key_sec1_hex();
        let p = EncryptionKeyPair::import_public_key_sec1_hex(&crate::EncryptionPublicKeyHex::new(&hex).unwrap()).unwrap();
        assert_eq!(p.export_public_key_sec1_hex(), hex); assert!(!p.has_private_key());
    }
    #[test] fn hpke_key_conversions_agree_with_sec1() {
        use hpke::Serializable;
        let kp = EncryptionKeyPair::generate();
        assert_eq!(kp.hpke_public().to_bytes().as_slice(), &kp.export_public_key_raw()[..]);
        assert!(kp.hpke_private().is_ok());
        assert!(matches!(EncryptionKeyPair::import_public_key_raw(&kp.export_public_key_raw()).unwrap().hpke_private(), Err(crate::Error::State(_))));
    }
}
