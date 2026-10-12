//! Port of dart_jwk_duo lib/src/key_duo_serializer.dart. Fixes bugs 1, 2, 9.
use crate::error::{format, Result};
use crate::interfaces::KeyPair;
use crate::{EncryptionKeyPair, EncryptionPublicKeyHex, KeyDuo, PublicKeyDuo, SigningKeyPair, SigningPublicKeyHex, ValidationService};
use serde_json::{Map, Value};

pub struct KeyDuoSerializer;

const KID_MISMATCH: &str = "JWK \"kid\" does not match the key's RFC 7638 thumbprint";

fn parse_set(json: &str) -> Result<Value> {
    match serde_json::from_str::<Value>(json) {
        Ok(v @ Value::Object(_)) => Ok(v),
        _ => Err(format("Invalid JSON format")),
    }
}

fn check_kid(m: &Map<String, Value>, computed: Result<String>) -> Result<()> {
    match m.get("kid") {
        Some(Value::String(k)) if *k == computed? => Ok(()),
        _ => Err(format(KID_MISMATCH)),
    }
}

fn find<'a>(set: &'a Value, use_: &str) -> &'a Map<String, Value> {
    set["keys"].as_array().expect("structure validated").iter()
        .filter_map(Value::as_object).find(|m| m.get("use").and_then(Value::as_str) == Some(use_))
        .expect("structure validated")
}

impl KeyDuoSerializer {
    pub fn export_key_duo_jwk(duo: &KeyDuo) -> Result<String> {
        let s = duo.signing_key_pair().export_private_key()?.to_json();
        let e = duo.encryption_key_pair().export_private_key()?.to_json();
        Ok(serde_json::json!({ "keys": [s, e] }).to_string())
    }
    pub fn export_public_key_duo_jwk(duo: &KeyDuo) -> Result<String> {
        let s = duo.signing_key_pair().export_public_key()?.to_json();
        let e = duo.encryption_key_pair().export_public_key()?.to_json();
        Ok(serde_json::json!({ "keys": [s, e] }).to_string())
    }
    pub fn import_key_duo_jwk(json: &str) -> Result<KeyDuo> { Self::import_from_value(&parse_set(json)?, true) }
    pub fn import_public_key_duo_jwk(json: &str) -> Result<KeyDuo> {
        Self::import_from_value(&ValidationService::extract_public_key_set(&parse_set(json)?)?, false)
    }

    fn import_from_value(set: &Value, private: bool) -> Result<KeyDuo> {
        ValidationService::validate_key_duo_jwk_structure(set)?;
        let sm = find(set, "sig");
        ValidationService::validate_signing_key(sm, private)?;
        let signing = SigningKeyPair::from_jwk_members(sm, private)?;
        check_kid(sm, signing.calculate_key_id())?;
        let em = find(set, "enc");
        ValidationService::validate_encryption_key(em, private)?;
        let encryption = EncryptionKeyPair::from_jwk_members(em, private)?;
        check_kid(em, encryption.calculate_key_id())?;
        // A rejection here is a malformed set, so it surfaces as a format error.
        KeyDuo::new(signing, encryption).map_err(|e| format(e.to_string()))
    }

    pub fn extract_signing_public_key_sec1_hex(json: &str) -> Result<SigningPublicKeyHex> {
        Ok(Self::import_for_extraction(json)?.signing_key_pair().typed_public_hex())
    }
    pub fn extract_encryption_public_key_sec1_hex(json: &str) -> Result<EncryptionPublicKeyHex> {
        Ok(Self::import_for_extraction(json)?.encryption_key_pair().typed_public_hex())
    }
    pub fn extract_public_key_duo(json: &str) -> Result<PublicKeyDuo> {
        Ok(Self::import_for_extraction(json)?.export_public_key_duo())
    }
    /// Every failure, including the top-level decode, is a format error (bug 9).
    fn import_for_extraction(json: &str) -> Result<KeyDuo> {
        Self::import_public_key_duo_jwk(json).map_err(|e| match e { crate::Error::Format(_) => e, other => format(format!("Invalid JWK Set: {other}")) })
    }
}

#[cfg(test)]
mod tests {
    use super::KeyDuoSerializer as S; use crate::*; use serde_json::Value;
    fn duo() -> KeyDuo { KeyDuo::new(SigningKeyPair::generate(), EncryptionKeyPair::generate()).unwrap() }
    #[test] fn export_structure_sig_first_and_round_trip() {
        let d = duo(); let j = S::export_key_duo_jwk(&d).unwrap(); let v: Value = serde_json::from_str(&j).unwrap();
        assert_eq!(v["keys"][0]["use"], "sig"); assert_eq!(v["keys"][1]["use"], "enc"); assert_eq!(v["keys"][1]["alg"], "HPKE-7");
        let back = S::import_key_duo_jwk(&j).unwrap(); assert_eq!(back.export_public_key_duo(), d.export_public_key_duo());
    }
    #[test] fn import_accepts_either_order() {
        let mut v: Value = serde_json::from_str(&S::export_key_duo_jwk(&duo()).unwrap()).unwrap();
        v["keys"].as_array_mut().unwrap().reverse();
        assert!(S::import_key_duo_jwk(&v.to_string()).is_ok());
    }
    #[test] fn import_rejects_kid_that_is_not_the_thumbprint() { // bug 1: validation_service.dart:102,144
        let other = duo(); let mut v: Value = serde_json::from_str(&S::export_key_duo_jwk(&duo()).unwrap()).unwrap();
        v["keys"][0]["kid"] = interfaces::KeyPair::calculate_key_id(other.signing_key_pair()).unwrap().into();
        assert!(matches!(S::import_key_duo_jwk(&v.to_string()), Err(Error::Format(m)) if m.contains("kid")));
    }
    #[test] fn import_rejects_identical_halves() { // bug 2: key_duo_serializer.dart:148
        let mut v: Value = serde_json::from_str(&S::export_key_duo_jwk(&duo()).unwrap()).unwrap();
        let s = v["keys"][0].clone();
        for k in ["x","y","d","kid"] { v["keys"][1][k] = s[k].clone(); }
        assert!(S::import_key_duo_jwk(&v.to_string()).is_err());
    }
    #[test] fn import_rejects_legacy_2x_encryption_alg() {
        let mut v: Value = serde_json::from_str(&S::export_key_duo_jwk(&duo()).unwrap()).unwrap();
        v["keys"][1]["alg"] = "ECDH-ES+A256KW".into(); assert!(S::import_key_duo_jwk(&v.to_string()).is_err());
    }
    #[test] fn public_import_strips_private_members_and_extractors_agree() {
        let d = duo(); let j = S::export_key_duo_jwk(&d).unwrap();
        assert!(!interfaces::KeyPair::has_private_key(S::import_public_key_duo_jwk(&j).unwrap().signing_key_pair()));
        assert_eq!(S::extract_public_key_duo(&j).unwrap(), d.export_public_key_duo());
    }
    #[test] fn extractor_non_string_and_bad_json_are_format_errors() { // bug 9: key_duo_serializer.dart:289; bug 4: :110
        assert!(matches!(S::extract_public_key_duo("not json"), Err(Error::Format(_))));
        assert!(matches!(S::extract_public_key_duo("[]"), Err(Error::Format(_))));
        assert!(matches!(S::import_key_duo_jwk(r#"{"keys":[{"use":5},{"use":"enc"}]}"#), Err(Error::Format(_))));
    }
}
