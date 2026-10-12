//! Port of dart_jwk_duo lib/src/validation_service.dart. Fixes bugs 4 and 8.
use crate::constants::{jwk_algorithm, jwk_curve, jwk_key_type, jwk_use};
use crate::error::{format, Result};
use serde_json::{Map, Value};

pub struct ValidationService;

/// `Ok(None)` when absent, `Ok(Some(&str))` for a string, a format error otherwise (bug 4).
fn opt_str<'a>(m: &'a Map<String, Value>, k: &str) -> Result<Option<&'a str>> {
    match m.get(k) {
        None => Ok(None),
        Some(Value::String(s)) => Ok(Some(s)),
        Some(_) => Err(format(format!("JWK member \"{k}\" must be a string"))),
    }
}

fn keys_array(set: &Value) -> Result<&Vec<Value>> {
    match set.get("keys") {
        Some(Value::Array(a)) => Ok(a),
        _ => Err(format("JWK Set \"keys\" must be an array")),
    }
}

fn parse_object(json: &str) -> Result<Map<String, Value>> {
    match serde_json::from_str::<Value>(json) {
        Ok(Value::Object(m)) => Ok(m),
        _ => Err(format("Invalid JSON format")),
    }
}

fn check_ec_key(m: &Map<String, Value>, require_private: bool, who: &str, alg: &str, use_: &str) -> Result<()> {
    if opt_str(m, "kty")? != Some(jwk_key_type::EC) { return Err(format(format!("{who} key must have type \"EC\""))); }
    if opt_str(m, "crv")? != Some(jwk_curve::P256) { return Err(format(format!("{who} key must use curve \"P-256\""))); }
    if opt_str(m, "alg")? != Some(alg) { return Err(format(format!("{who} key must have algorithm \"{alg}\""))); }
    if opt_str(m, "use")? != Some(use_) { return Err(format(format!("{who} key must have use \"{use_}\""))); }
    if !m.contains_key("x") || !m.contains_key("y") { return Err(format("EC key missing required x/y coordinates")); }
    if require_private && !m.contains_key("d") { return Err(format("Private key must contain private component \"d\"")); }
    if !m.contains_key("kid") { return Err(format("Key must contain key identifier \"kid\"")); }
    Ok(())
}

impl ValidationService {
    pub fn validate_key_duo_jwk_structure(jwk_set: &Value) -> Result<()> {
        if jwk_set.get("keys").is_none() { return Err(format("JWK Set must contain \"keys\" array")); }
        let keys = keys_array(jwk_set)?;
        if keys.len() != 2 { return Err(format("JWK Set must contain exactly 2 keys")); }
        let (mut sig, mut enc) = (false, false);
        for key in keys {
            let Value::Object(m) = key else { return Err(format("Each key in JWK Set must be an object")) };
            match opt_str(m, "use")? {
                Some(jwk_use::SIGNATURE) => {
                    if sig { return Err(format("JWK Set contains multiple signing keys")); }
                    sig = true;
                }
                Some(jwk_use::ENCRYPTION) => {
                    if enc { return Err(format("JWK Set contains multiple encryption keys")); }
                    enc = true;
                }
                _ => return Err(format("Invalid key use. Must be \"sig\" or \"enc\"")),
            }
        }
        if !sig { return Err(format("JWK Set must contain a signing key (use=\"sig\")")); }
        if !enc { return Err(format("JWK Set must contain an encryption key (use=\"enc\")")); }
        Ok(())
    }

    /// Port of `validateEcdsaKey`.
    pub fn validate_signing_key(key: &Map<String, Value>, require_private: bool) -> Result<()> {
        check_ec_key(key, require_private, "Signing", jwk_algorithm::ES256, jwk_use::SIGNATURE)
    }

    /// Port of `validateEcdhKey`; `alg` must be `HPKE-7`.
    pub fn validate_encryption_key(key: &Map<String, Value>, require_private: bool) -> Result<()> {
        check_ec_key(key, require_private, "Encryption", jwk_algorithm::HPKE7, jwk_use::ENCRYPTION)
    }

    pub fn validate_symmetric_key_jwk(key: &Map<String, Value>) -> Result<()> {
        if opt_str(key, "kty")? != Some(jwk_key_type::OCT) { return Err(format("Symmetric key must have type \"oct\"")); }
        if !key.contains_key("k") { return Err(format("Symmetric key missing required \"k\" component")); }
        Ok(())
    }

    pub fn extract_public_key_fields(key: &Map<String, Value>) -> Map<String, Value> {
        let mut out = Map::new();
        for k in ["kty", "crv", "x", "y", "alg", "use", "kid"] {
            if let Some(v) = key.get(k) { out.insert(k.into(), v.clone()); }
        }
        out
    }

    pub fn extract_public_key_set(jwk_set: &Value) -> Result<Value> {
        let mut out = Vec::new();
        for key in keys_array(jwk_set)? {
            let Value::Object(m) = key else { return Err(format("Each key in JWK Set must be an object")) };
            out.push(Value::Object(Self::extract_public_key_fields(m)));
        }
        Ok(serde_json::json!({ "keys": out }))
    }

    pub fn validate_no_private_key_material(jwk_set: &Value) -> Result<()> {
        for key in keys_array(jwk_set)? {
            let Value::Object(m) = key else { return Err(format("Each key in JWK Set must be an object")) };
            let found: Vec<&str> = ["d", "p", "q", "dp", "dq", "qi", "oth"].into_iter().filter(|c| m.contains_key(*c)).collect();
            if !found.is_empty() {
                return Err(format(format!("Private key material detected: {}. Use importKeyDuoJwk() for private keys.", found.join(", "))));
            }
        }
        Ok(())
    }

    pub fn validate_key_duo_jwk(jwk_set_json: &str) -> Result<()> {
        let set = Value::Object(parse_object(jwk_set_json)?);
        Self::validate_key_duo_jwk_structure(&set)?;
        for key in keys_array(&set)? {
            let Value::Object(m) = key else { continue };
            match opt_str(m, "use")? {
                Some(jwk_use::SIGNATURE) => Self::validate_signing_key(m, false)?,
                Some(jwk_use::ENCRYPTION) => Self::validate_encryption_key(m, false)?,
                _ => {}
            }
        }
        Ok(())
    }

    pub fn validate_symmetric_key_jwk_string(jwk: &str) -> Result<()> {
        Self::validate_symmetric_key_jwk(&parse_object(jwk)?)
    }
}

#[cfg(test)]
mod tests {
    use super::ValidationService as V; use crate::Error; use serde_json::json;
    fn sig() -> serde_json::Value { json!({"kty":"EC","crv":"P-256","x":"x","y":"y","kid":"k","alg":"ES256","use":"sig"}) }
    fn enc() -> serde_json::Value { json!({"kty":"EC","crv":"P-256","x":"x","y":"y","kid":"k","alg":"HPKE-7","use":"enc"}) }
    #[test] fn structure_requires_exactly_one_sig_and_one_enc() {
        assert!(V::validate_key_duo_jwk_structure(&json!({"keys":[sig(),enc()]})).is_ok());
        assert!(V::validate_key_duo_jwk_structure(&json!({"keys":[sig(),sig()]})).is_err());
        assert!(V::validate_key_duo_jwk_structure(&json!({"keys":[sig()]})).is_err());
        assert!(V::validate_key_duo_jwk_structure(&json!({})).is_err());
    }
    #[test] fn non_string_and_non_object_members_are_format_errors() { // bug 4
        for bad in [json!({"keys":{}}), json!({"keys":[3, enc()]}), json!({"keys":[{"use":5}, enc()]})] {
            assert!(matches!(V::validate_key_duo_jwk_structure(&bad), Err(Error::Format(_))), "{bad}");
        }
        let mut s = sig(); s["kty"] = json!(5);
        assert!(matches!(V::validate_signing_key(s.as_object().unwrap(), false), Err(Error::Format(_))));
    }
    #[test] fn encryption_key_alg_must_be_hpke7_and_legacy_label_is_rejected() {
        let mut e = enc(); e["alg"] = json!("ECDH-ES+A256KW");
        assert!(matches!(V::validate_encryption_key(e.as_object().unwrap(), false), Err(Error::Format(m)) if m.contains("HPKE-7")));
    }
    #[test] fn private_requires_d_and_kid_is_required() {
        assert!(V::validate_signing_key(sig().as_object().unwrap(), true).is_err());
        let mut s = sig(); s.as_object_mut().unwrap().remove("kid"); assert!(V::validate_signing_key(s.as_object().unwrap(), false).is_err());
    }
    #[test] fn no_private_material_rejects_malformed_sets() { // bug 8: validation_service.dart:222,224
        assert!(matches!(V::validate_no_private_key_material(&json!({"keys":{}})), Err(Error::Format(_))));
        assert!(matches!(V::validate_no_private_key_material(&json!({"keys":[3]})), Err(Error::Format(_))));
        assert!(matches!(V::validate_no_private_key_material(&json!({"keys":[{"d":"x"}]})), Err(Error::Format(m)) if m.contains("d")));
    }
    #[test] fn public_set_extraction_keeps_only_public_members() {
        let mut s = sig(); s["d"] = json!("secret");
        let out = V::extract_public_key_set(&json!({"keys":[s, enc()]})).unwrap();
        assert!(out["keys"][0].get("d").is_none()); assert_eq!(out["keys"][0]["kid"], "k");
    }
}
