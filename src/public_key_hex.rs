//! Port of dart_jwk_duo lib/src/public_key_hex.dart.
use crate::error::{argument, format, Result};
use crate::Sec1PublicKey;

macro_rules! typed_hex {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub struct $name(String);
        impl $name {
            pub fn new(sec1_hex: &str) -> Result<Self> {
                Sec1PublicKey::decode_hex(sec1_hex)?;
                Ok(Self(sec1_hex.to_ascii_lowercase()))
            }
            pub fn value(&self) -> &str { &self.0 }
        }
    };
}
typed_hex!(SigningPublicKeyHex);
typed_hex!(EncryptionPublicKeyHex);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PublicKeyDuo { pub signing: SigningPublicKeyHex, pub encryption: EncryptionPublicKeyHex }

impl PublicKeyDuo {
    pub const SIGNING_JSON_KEY: &'static str = "signingPublicKeyHex";
    pub const ENCRYPTION_JSON_KEY: &'static str = "encryptionPublicKeyHex";
    pub fn new(signing: SigningPublicKeyHex, encryption: EncryptionPublicKeyHex) -> Result<Self> {
        if signing.value() == encryption.value() {
            return Err(argument("Signing and encryption public keys are identical. One key has been placed in both fields; they must come from different key pairs."));
        }
        Ok(Self { signing, encryption })
    }
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({ Self::SIGNING_JSON_KEY: self.signing.value(), Self::ENCRYPTION_JSON_KEY: self.encryption.value() })
    }
    pub fn from_json(json: &serde_json::Value) -> Result<Self> {
        let get = |k: &str| json.get(k).and_then(|v| v.as_str()).ok_or_else(|| format(format!("Missing or non-string \"{k}\"")));
        Self::new(SigningPublicKeyHex::new(get(Self::SIGNING_JSON_KEY)?)?, EncryptionPublicKeyHex::new(get(Self::ENCRYPTION_JSON_KEY)?)?)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;
    fn k(b: u8) -> String { format!("04{}", format!("{b:02x}").repeat(64)) }
    #[test] fn wraps_a_valid_sec1_hex_string_and_lowercases() {
        let up = k(0xab).to_uppercase();
        assert_eq!(SigningPublicKeyHex::new(&up).unwrap().value(), k(0xab));
    }
    #[test] fn rejects_anything_not_sec1() { assert!(matches!(SigningPublicKeyHex::new("04"), Err(Error::Format(_)))); }
    #[test] fn encryption_wrapper_validates_identically() { assert!(EncryptionPublicKeyHex::new(&k(1)).is_ok()); assert!(EncryptionPublicKeyHex::new("zz").is_err()); }
    #[test] fn duo_rejects_identical_halves() {
        let r = PublicKeyDuo::new(SigningPublicKeyHex::new(&k(1)).unwrap(), EncryptionPublicKeyHex::new(&k(1)).unwrap());
        assert!(matches!(r, Err(Error::Argument(_))));
    }
    #[test] fn duo_round_trips_through_json_with_purpose_named_keys() {
        let d = PublicKeyDuo::new(SigningPublicKeyHex::new(&k(1)).unwrap(), EncryptionPublicKeyHex::new(&k(2)).unwrap()).unwrap();
        let j = d.to_json();
        assert_eq!(j["signingPublicKeyHex"], k(1)); assert_eq!(j["encryptionPublicKeyHex"], k(2));
        assert_eq!(PublicKeyDuo::from_json(&j).unwrap(), d);
    }
    #[test] fn from_json_rejects_missing_or_non_string() {
        assert!(matches!(PublicKeyDuo::from_json(&serde_json::json!({"signingPublicKeyHex": 5})), Err(Error::Format(_))));
        assert!(matches!(PublicKeyDuo::from_json(&serde_json::json!({})), Err(Error::Format(_))));
    }
}
