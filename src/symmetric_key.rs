//! Port of dart_jwk_duo lib/src/symmetric_key.dart. Fixes bug 5 (256-bit only).
use crate::constants::{crypto_sizes::AES_256_KEY_LENGTH, jwk_algorithm, jwk_key_type, jwk_use};
use crate::error::{format, Result};
use crate::jwk::{b64u_decode_exact, b64u_encode};
use zeroize::Zeroizing;

pub struct SymmetricKey(Zeroizing<[u8; AES_256_KEY_LENGTH]>);

impl std::fmt::Debug for SymmetricKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str("SymmetricKey(..)") }
}

fn wrap(reason: impl std::fmt::Display) -> crate::Error { format(format!("Failed to import symmetric key: {reason}")) }

impl SymmetricKey {
    pub fn generate() -> Self {
        let mut b = Zeroizing::new([0u8; AES_256_KEY_LENGTH]);
        getrandom::fill(b.as_mut()).expect("OS RNG unavailable");
        Self(b)
    }
    pub fn from_jwk(json: &str) -> Result<Self> {
        let v: serde_json::Value = serde_json::from_str(json).map_err(|_| format("Invalid JSON format"))?;
        let m = v.as_object().ok_or_else(|| wrap("JWK must be an object"))?;
        if m.get("kty").and_then(|x| x.as_str()) != Some(jwk_key_type::OCT) { return Err(wrap("kty must be \"oct\"")); }
        let k = m.get("k").and_then(|x| x.as_str()).ok_or_else(|| wrap("missing or non-string \"k\""))?;
        match m.get("alg") {
            None => {}
            Some(serde_json::Value::String(a)) if a == jwk_algorithm::A256GCM => {}
            Some(_) => return Err(wrap("alg must be \"A256GCM\"")),
        }
        let bytes = Zeroizing::new(b64u_decode_exact(k, AES_256_KEY_LENGTH).map_err(wrap)?);
        let mut key = Zeroizing::new([0u8; AES_256_KEY_LENGTH]);
        key.copy_from_slice(&bytes);
        Ok(Self(key))
    }
    pub fn to_jwk(&self) -> String {
        serde_json::json!({"kty": jwk_key_type::OCT, "k": b64u_encode(&*self.0), "alg": jwk_algorithm::A256GCM, "use": jwk_use::ENCRYPTION}).to_string()
    }
    pub(crate) fn cipher(&self) -> aes_gcm::Aes256Gcm {
        use aes_gcm::KeyInit;
        aes_gcm::Aes256Gcm::new_from_slice(&*self.0).expect("32-byte key")
    }
    #[cfg(test)]
    pub(crate) fn __raw_for_tests(&self) -> &[u8] { &*self.0 }
}

#[cfg(test)]
mod tests {
    use super::*; use crate::Error;
    #[test] fn jwk_round_trip() { let k = SymmetricKey::generate(); let j = k.to_jwk(); assert_eq!(SymmetricKey::from_jwk(&j).unwrap().to_jwk(), j); }
    #[test] fn rejects_128_bit_keys() { // bug 5: symmetric_key.dart:34
        let j = format!(r#"{{"kty":"oct","k":"{}","alg":"A128GCM"}}"#, crate::jwk::b64u_encode(&[1u8; 16]));
        assert!(matches!(SymmetricKey::from_jwk(&j), Err(Error::Format(_))));
        // length is enforced independently of the alg label
        let no_alg = format!(r#"{{"kty":"oct","k":"{}"}}"#, crate::jwk::b64u_encode(&[1u8; 16]));
        assert!(matches!(SymmetricKey::from_jwk(&no_alg), Err(Error::Format(_))));
    }
    #[test] fn rejects_256_bit_key_labelled_a128gcm_and_non_string_alg() {
        let k = crate::jwk::b64u_encode(&[1u8; 32]);
        assert!(matches!(SymmetricKey::from_jwk(&format!(r#"{{"kty":"oct","k":"{k}","alg":"A128GCM"}}"#)), Err(Error::Format(_))));
        assert!(matches!(SymmetricKey::from_jwk(&format!(r#"{{"kty":"oct","k":"{k}","alg":5}}"#)), Err(Error::Format(_))));
    }
    #[test] fn debug_never_prints_the_key() {
        let k = SymmetricKey::generate(); let raw = crate::jwk::b64u_encode(k.__raw_for_tests());
        assert!(!format!("{k:?}").contains(&raw));
    }
    #[test] fn rejects_non_oct_bad_json_and_padded_k() {
        assert!(SymmetricKey::from_jwk(r#"{"kty":"EC"}"#).is_err());
        assert!(SymmetricKey::from_jwk("not json").is_err());
        let j = format!(r#"{{"kty":"oct","k":"{}="}}"#, crate::jwk::b64u_encode(&[1u8; 32]));
        assert!(SymmetricKey::from_jwk(&j).is_err());
    }
}
