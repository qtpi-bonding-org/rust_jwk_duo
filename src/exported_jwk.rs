//! Port of dart_jwk_duo lib/src/exported_jwk.dart. Fixes bug 7.
use crate::constants::{jwk_algorithm, jwk_key_type, jwk_use};
use crate::error::{argument, format, Result};
use serde_json::{Map, Value};

/// A validated JWK export. All fields are private: the only constructor is
/// crate-internal `new`, which enforces the alg/use/kty invariants, and there
/// is no mutation API, so an invalid value cannot exist.
///
/// ```compile_fail
/// use rust_jwk_duo::ExportedJwk;
/// fn tamper(jwk: &mut ExportedJwk) { jwk.alg = "x".into(); }
/// ```
///
/// ```compile_fail
/// use rust_jwk_duo::ExportedJwk;
/// fn read(jwk: &ExportedJwk) -> &str { &jwk.use_ }
/// ```
///
/// ```compile_fail
/// use rust_jwk_duo::ExportedJwk;
/// fn forge() -> ExportedJwk {
///     ExportedJwk { key_id: String::new(), alg: "x".into(), use_: "y".into() }
/// }
/// ```
#[derive(Clone, PartialEq)]
pub struct ExportedJwk { key_data: Map<String, Value>, key_id: String, alg: String, use_: String }

/// Redacting Debug: key data may hold `d`; secrets never appear in Debug.
impl std::fmt::Debug for ExportedJwk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExportedJwk").field("key_id", &self.key_id).field("alg", &self.alg).field("use_", &self.use_)
            .field("has_private_member", &self.key_data.contains_key("d")).finish()
    }
}

impl ExportedJwk {
    pub(crate) fn new(key_data: Map<String, Value>, key_id: String, alg: &str, use_: &str) -> Result<Self> {
        let s = Self { key_data, key_id, alg: alg.into(), use_: use_.into() };
        s.validate()?;
        Ok(s)
    }
    pub fn key_id(&self) -> &str { &self.key_id }
    pub fn alg(&self) -> &str { &self.alg }
    pub fn use_(&self) -> &str { &self.use_ }
    fn kty(&self) -> Option<&str> { self.key_data.get("kty").and_then(Value::as_str) }
    fn validate(&self) -> Result<()> {
        let is_ec = self.kty() == Some(jwk_key_type::EC);
        match self.alg.as_str() {
            jwk_algorithm::ES256 => {
                if self.use_ != jwk_use::SIGNATURE { return Err(argument("ES256 algorithm must be used with \"sig\" use")); }
                if !is_ec { return Err(argument("ES256 algorithm requires EC key type")); }
            }
            jwk_algorithm::HPKE7 => {
                if self.use_ != jwk_use::ENCRYPTION { return Err(argument("HPKE-7 algorithm must be used with \"enc\" use")); }
                if !is_ec { return Err(argument("HPKE-7 algorithm requires EC key type")); }
            }
            _ => {}
        }
        if self.use_ == jwk_use::SIGNATURE && self.alg != jwk_algorithm::ES256 { return Err(argument("Signature use must be used with ES256 algorithm")); }
        if self.use_ == jwk_use::ENCRYPTION && self.alg != jwk_algorithm::HPKE7 { return Err(argument("Encryption use must be used with HPKE-7 algorithm")); }
        Ok(())
    }
    pub fn to_json(&self) -> Map<String, Value> {
        let mut m = self.key_data.clone();
        m.insert("kid".into(), self.key_id.clone().into());
        m.insert("alg".into(), self.alg.clone().into());
        m.insert("use".into(), self.use_.clone().into());
        m
    }
    pub fn to_public_only(&self) -> Result<ExportedJwk> {
        if self.kty() != Some(jwk_key_type::EC) { return Err(format("Unknown key type")); }
        let mut pd = Map::new();
        for k in ["kty", "crv", "x", "y"] {
            pd.insert(k.into(), self.key_data.get(k).cloned().ok_or_else(|| format("Cannot create public key: missing required components"))?);
        }
        ExportedJwk::new(pd, self.key_id.clone(), &self.alg, &self.use_)
    }
}
#[cfg(test)]
mod tests {
    use super::*; use crate::constants::{jwk_algorithm, jwk_use}; use crate::Error; use serde_json::json;
    fn ec() -> serde_json::Map<String, serde_json::Value> { json!({"kty":"EC","crv":"P-256","x":"a","y":"b","d":"c"}).as_object().unwrap().clone() }
    #[test] fn sig_needs_es256_and_enc_needs_hpke7() {
        assert!(ExportedJwk::new(ec(), "k".into(), jwk_algorithm::ES256, jwk_use::SIGNATURE).is_ok());
        assert!(ExportedJwk::new(ec(), "k".into(), jwk_algorithm::HPKE7, jwk_use::ENCRYPTION).is_ok());
        assert!(matches!(ExportedJwk::new(ec(), "k".into(), jwk_algorithm::ES256, jwk_use::ENCRYPTION), Err(Error::Argument(_))));
        assert!(matches!(ExportedJwk::new(ec(), "k".into(), "ECDH-ES+A256KW", jwk_use::ENCRYPTION), Err(Error::Argument(_))));
    }
    #[test] fn to_json_merges_metadata_and_public_only_drops_d() {
        let e = ExportedJwk::new(ec(), "kid1".into(), jwk_algorithm::ES256, jwk_use::SIGNATURE).unwrap();
        let j = e.to_json(); assert_eq!(j["kid"], "kid1"); assert_eq!(j["use"], "sig");
        assert!(e.to_public_only().unwrap().to_json().get("d").is_none());
    }
    #[test] fn debug_never_prints_private_members() {
        let e = ExportedJwk::new(ec(), "k".into(), jwk_algorithm::ES256, jwk_use::SIGNATURE).unwrap();
        let dbg = format!("{e:?}"); assert!(!dbg.contains("\"d\"") && !dbg.contains("\"c\""));
    }
    #[test] fn non_string_kty_is_an_argument_error_not_a_panic() { // bug 7: exported_jwk.dart:53,82
        let mut m = ec(); m.insert("kty".into(), json!(5));
        assert!(matches!(ExportedJwk::new(m, "k".into(), jwk_algorithm::ES256, jwk_use::SIGNATURE), Err(Error::Argument(_))));
    }
}
