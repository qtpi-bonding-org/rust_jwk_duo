//! Port of dart_jwk_duo lib/src/signing_key_pair.dart.
use crate::constants::{jwk_algorithm, jwk_use};
use crate::error::{format, state, Result};
use crate::interfaces::KeyPair;
use crate::{calculate_jwk_thumbprint, jwk, ExportedJwk, Sec1PublicKey, SigningPublicKeyHex};
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};

pub struct SigningKeyPair { private: Option<SigningKey>, public: VerifyingKey }

impl SigningKeyPair {
    /// Fresh key from the library's own generator (p256 `Generate`, OS RNG).
    pub fn generate() -> Self {
        use p256::elliptic_curve::Generate;
        let sk = SigningKey::from(&p256::SecretKey::generate());
        let public = *sk.verifying_key();
        Self { private: Some(sk), public }
    }
    pub fn import_public_key_raw(raw: &[u8]) -> Result<Self> {
        let pk = Sec1PublicKey::import_p256(raw)?;
        Ok(Self { private: None, public: VerifyingKey::from(&pk) })
    }
    pub fn import_public_key_sec1_hex(hex: &SigningPublicKeyHex) -> Result<Self> {
        Self::import_public_key_raw(&Sec1PublicKey::decode_hex(hex.value())?)
    }
    pub(crate) fn from_jwk_members(m: &serde_json::Map<String, serde_json::Value>, private: bool) -> Result<Self> {
        if private {
            let sk = jwk::parse_ec_private(m)?;
            let sk = SigningKey::from(&sk);
            let public = *sk.verifying_key();
            Ok(Self { private: Some(sk), public })
        } else {
            Ok(Self { private: None, public: VerifyingKey::from(&jwk::parse_ec_public(m)?) })
        }
    }
    pub fn sign_bytes(&self, data: &[u8]) -> Result<[u8; 64]> {
        let sk = self.private.as_ref().ok_or_else(|| state("Cannot sign: public-only key pair"))?;
        let sig: Signature = sk.sign(data);
        Ok(sig.to_bytes().into())
    }
    /// false (never an error) for any malformed signature, matching 2.x.
    pub fn verify_bytes(&self, signature: &[u8], data: &[u8]) -> bool {
        Signature::from_slice(signature).map(|s| self.public.verify(data, &s).is_ok()).unwrap_or(false)
    }
    pub fn signature_from_der(der: &[u8]) -> Result<[u8; 64]> {
        Signature::from_der(der).map(|s| s.to_bytes().into()).map_err(|_| format("Invalid DER ECDSA signature"))
    }
    pub fn signature_to_der(sig: &[u8; 64]) -> Result<Vec<u8>> {
        Signature::from_slice(sig).map(|s| s.to_der().as_bytes().to_vec()).map_err(|_| format("Invalid P1363 ECDSA signature"))
    }
    pub fn typed_public_hex(&self) -> SigningPublicKeyHex {
        SigningPublicKeyHex::new(&self.export_public_key_sec1_hex()).expect("own key is valid SEC1")
    }
    fn public_p256(&self) -> p256::PublicKey { p256::PublicKey::from(&self.public) }
}

impl KeyPair for SigningKeyPair {
    fn has_private_key(&self) -> bool { self.private.is_some() }
    fn export_private_key(&self) -> Result<ExportedJwk> {
        let sk = self.private.as_ref().ok_or_else(|| state("Cannot export private key: public-only key pair"))?;
        let secret = p256::SecretKey::from(sk);
        ExportedJwk::new(jwk::ec_private_members(&secret), self.calculate_key_id()?, jwk_algorithm::ES256, jwk_use::SIGNATURE)
    }
    fn export_public_key(&self) -> Result<ExportedJwk> {
        ExportedJwk::new(jwk::ec_public_members(&self.public_p256()), self.calculate_key_id()?, jwk_algorithm::ES256, jwk_use::SIGNATURE)
    }
    fn export_public_key_raw(&self) -> [u8; 65] { Sec1PublicKey::export_p256(&self.public_p256()) }
    fn calculate_key_id(&self) -> Result<String> { calculate_jwk_thumbprint(&jwk::ec_public_members(&self.public_p256())) }
}

impl std::fmt::Debug for SigningKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningKeyPair").field("public", &self.export_public_key_sec1_hex()).field("has_private_key", &self.private.is_some()).finish()
    }
}
#[cfg(test)]
mod tests {
    use super::*; use crate::interfaces::KeyPair; use crate::Error;
    #[test] fn export_includes_correct_metadata_and_kid_is_thumbprint() {
        let kp = SigningKeyPair::generate();
        let j = kp.export_private_key().unwrap().to_json();
        assert_eq!(j["alg"], "ES256"); assert_eq!(j["use"], "sig"); assert!(j.get("d").is_some());
        assert_eq!(j["kid"], kp.calculate_key_id().unwrap().as_str());
        assert!(kp.export_public_key().unwrap().to_json().get("d").is_none());
    }
    #[test] fn sign_and_verify() {
        let kp = SigningKeyPair::generate(); let sig = kp.sign_bytes(b"hello").unwrap();
        assert_eq!(sig.len(), 64); assert!(kp.verify_bytes(&sig, b"hello")); assert!(!kp.verify_bytes(&sig, b"hellp"));
    }
    #[test] fn sec1_round_trip_is_byte_identical_and_still_verifies() {
        let kp = SigningKeyPair::generate(); let hex = kp.export_public_key_sec1_hex();
        let pubonly = SigningKeyPair::import_public_key_sec1_hex(&crate::SigningPublicKeyHex::new(&hex).unwrap()).unwrap();
        assert_eq!(pubonly.export_public_key_sec1_hex(), hex);
        assert!(pubonly.verify_bytes(&kp.sign_bytes(b"m").unwrap(), b"m"));
        assert!(matches!(pubonly.sign_bytes(b"m"), Err(Error::State(_))));
    }
    #[test] fn high_s_signature_verifies() {
        // p256 does not normalise, so a native signature is high-S about half
        // the time. Normalise first, then negate, so `high` is always high-S.
        let kp = SigningKeyPair::generate(); let sig = kp.sign_bytes(b"m").unwrap();
        let low = p256::ecdsa::Signature::from_slice(&sig).unwrap().normalize_s();
        let (r, s_) = low.split_scalars();
        let high = p256::ecdsa::Signature::from_scalars(r, -*s_).unwrap(); // n - s
        assert_eq!(low.normalize_s(), low); assert_ne!(high.normalize_s(), high);
        let lb: [u8; 64] = low.to_bytes().into(); let hb: [u8; 64] = high.to_bytes().into();
        assert!(kp.verify_bytes(&lb, b"m")); assert!(kp.verify_bytes(&hb, b"m"));
    }
    #[test] fn malformed_signatures_return_false_not_error() {
        let kp = SigningKeyPair::generate();
        assert!(!kp.verify_bytes(&[0u8; 64], b"m")); assert!(!kp.verify_bytes(&[1u8; 10], b"m"));
    }
    #[test] fn der_round_trip() {
        let kp = SigningKeyPair::generate(); let sig = kp.sign_bytes(b"m").unwrap();
        let der = SigningKeyPair::signature_to_der(&sig).unwrap();
        assert_eq!(SigningKeyPair::signature_from_der(&der).unwrap(), sig);
        assert!(matches!(SigningKeyPair::signature_from_der(&[0x30, 0x00]), Err(Error::Format(_))));
    }
}
