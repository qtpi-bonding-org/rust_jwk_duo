//! Port of dart_jwk_duo lib/src/jwk_thumbprint.dart (RFC 7638, EC only).
use crate::error::{argument, Result};
use base64ct::{Base64UrlUnpadded, Encoding};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

pub fn calculate_jwk_thumbprint(jwk: &Map<String, Value>) -> Result<String> {
    let kty = match jwk.get("kty") {
        None => return Err(argument("Missing required JWK member: kty is required")),
        Some(Value::String(s)) => s.as_str(),
        Some(_) => return Err(argument("JWK member \"kty\" must be a String")),
    };
    if kty != "EC" { return Err(argument("Only EC keys are supported for thumbprint calculation")); }
    let (crv, x, y) = match (jwk.get("crv"), jwk.get("x"), jwk.get("y")) {
        (Some(Value::String(c)), Some(Value::String(x)), Some(Value::String(y))) => (c, x, y),
        (None, _, _) | (_, None, _) | (_, _, None) => return Err(argument("Missing required JWK member: crv, x, and y are required for EC keys")),
        _ => return Err(argument("JWK members crv, x, and y must be strings")),
    };
    let q = |s: &str| serde_json::to_string(s).expect("string serializes");
    let canonical = format!("{{\"crv\":{},\"kty\":{},\"x\":{},\"y\":{}}}", q(crv), q(kty), q(x), q(y));
    Ok(Base64UrlUnpadded::encode_string(&Sha256::digest(canonical.as_bytes())))
}
#[cfg(test)]
mod tests {
    use super::*; use crate::Error;
    #[test] fn deterministic_and_ignores_extra_members() {
        let m: serde_json::Map<_, _> = serde_json::from_str(r#"{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","kid":"z","alg":"ES256"}"#).unwrap();
        let t1 = calculate_jwk_thumbprint(&m).unwrap();
        let mut m2 = m.clone(); m2.remove("kid");
        assert_eq!(t1, calculate_jwk_thumbprint(&m2).unwrap());
        assert_eq!(t1.len(), 43); assert!(!t1.contains('='));
    }
    /// Known answer: draft-ietf-jose-hpke-encrypt-22 Appendix A.13 (HPKE-7 key).
    /// RFC 7638 §3.1 has only an RSA example, so this EC vector is the pin.
    #[test] fn jose_hpke_a13_known_answer() {
        let m: serde_json::Map<_, _> = serde_json::from_str(r#"{"kty":"EC","crv":"P-256","x":"z860carZ9CSxTjXo7MK65h_TaZX7ipi2iUh_Bh-VP54","y":"i9X0v8PwcNgbsoMhAz-_W2OPaFU--BQAgWVzJVOfedo"}"#).unwrap();
        assert_eq!(calculate_jwk_thumbprint(&m).unwrap(), "YGdLPiZno0vV3kJKu4kEMQEjK3_upFF2D_lFDf1FFwk");
    }
    #[test] fn validation_errors_are_argument_errors() {
        let m: serde_json::Map<_, _> = serde_json::from_str(r#"{"kty":"RSA"}"#).unwrap();
        assert!(matches!(calculate_jwk_thumbprint(&m), Err(Error::Argument(_))));
        let m: serde_json::Map<_, _> = serde_json::from_str(r#"{"kty":"EC","crv":"P-256","x":1,"y":"a"}"#).unwrap();
        assert!(matches!(calculate_jwk_thumbprint(&m), Err(Error::Argument(_))));
    }
}
