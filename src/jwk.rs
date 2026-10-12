//! JWK member handling. Replaces webcrypto's importJsonWebKey/exportJsonWebKey
//! (p256 0.14 has no `jwk` feature). Encoding only; no cryptography here.
//! Fixes bug 3 (strict base64url) and bug 6 (d must match x/y).
use crate::constants::{crypto_sizes::EC_P256_COORDINATE_LENGTH as L, jwk_curve, jwk_key_type};
use crate::error::{format, Result};
use crate::Sec1PublicKey;
use base64ct::{Base64UrlUnpadded, Encoding};
use serde_json::{Map, Value};

pub(crate) fn b64u_encode(bytes: &[u8]) -> String { Base64UrlUnpadded::encode_string(bytes) }

pub(crate) fn b64u_decode_exact(s: &str, len: usize) -> Result<Vec<u8>> {
    let bytes = Base64UrlUnpadded::decode_vec(s).map_err(|_| format("JWK member is not unpadded base64url"))?;
    if bytes.len() != len { return Err(format(format!("JWK member must decode to {len} bytes (got {})", bytes.len()))); }
    Ok(bytes)
}

fn str_member<'a>(m: &'a Map<String, Value>, k: &str) -> Result<&'a str> {
    match m.get(k) {
        Some(Value::String(s)) => Ok(s),
        Some(_) => Err(format(format!("JWK member \"{k}\" must be a string"))),
        None => Err(format(format!("JWK missing required member \"{k}\""))),
    }
}

pub(crate) fn ec_public_members(pk: &p256::PublicKey) -> Map<String, Value> {
    let raw = Sec1PublicKey::export_p256(pk);
    let mut m = Map::new();
    m.insert("kty".into(), jwk_key_type::EC.into());
    m.insert("crv".into(), jwk_curve::P256.into());
    m.insert("x".into(), b64u_encode(&raw[1..33]).into());
    m.insert("y".into(), b64u_encode(&raw[33..65]).into());
    m
}

pub(crate) fn ec_private_members(sk: &p256::SecretKey) -> Map<String, Value> {
    let mut m = ec_public_members(&sk.public_key());
    m.insert("d".into(), b64u_encode(&sk.to_bytes()).into());
    m
}

pub(crate) fn parse_ec_public(m: &Map<String, Value>) -> Result<p256::PublicKey> {
    if str_member(m, "kty")? != jwk_key_type::EC { return Err(format("JWK \"kty\" must be \"EC\"")); }
    if str_member(m, "crv")? != jwk_curve::P256 { return Err(format("JWK \"crv\" must be \"P-256\"")); }
    let x = b64u_decode_exact(str_member(m, "x")?, L)?;
    let y = b64u_decode_exact(str_member(m, "y")?, L)?;
    let mut raw = Vec::with_capacity(65); raw.push(0x04); raw.extend(x); raw.extend(y);
    Sec1PublicKey::import_p256(&raw)
}

pub(crate) fn parse_ec_private(m: &Map<String, Value>) -> Result<p256::SecretKey> {
    let public = parse_ec_public(m)?;
    let d = zeroize::Zeroizing::new(b64u_decode_exact(str_member(m, "d")?, L)?);
    let sk = p256::SecretKey::from_slice(&d).map_err(|_| format("JWK \"d\" is not a valid P-256 scalar"))?;
    if sk.public_key() != public { return Err(format("JWK private key \"d\" does not match its \"x\"/\"y\"")); }
    Ok(sk)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;
    fn key() -> p256::SecretKey { p256::SecretKey::from_slice(&[7u8; 32]).unwrap() }
    #[test] fn private_round_trip() {
        let sk = key(); let m = ec_private_members(&sk);
        assert_eq!(parse_ec_private(&m).unwrap().to_bytes(), sk.to_bytes());
        assert_eq!(parse_ec_public(&m).unwrap(), sk.public_key());
    }
    #[test] fn private_jwk_with_mismatched_d_is_rejected() {
        let mut m = ec_private_members(&key());
        let other = p256::SecretKey::from_slice(&[9u8; 32]).unwrap();
        m.insert("d".into(), b64u_encode(&other.to_bytes()).into());
        assert!(matches!(parse_ec_private(&m), Err(Error::Format(msg)) if msg.contains("does not match")));
    }
    #[test] fn base64_is_strict_no_padding_no_standard_alphabet_exact_length() {
        let good = b64u_encode(&[0xfb; 32]); // contains '-' or '_' for 0xfb runs
        assert!(b64u_decode_exact(&good, 32).is_ok());
        assert!(b64u_decode_exact(&format!("{good}="), 32).is_err());
        assert!(b64u_decode_exact(&good.replace('-', "+").replace('_', "/"), 32).is_err());
        assert!(b64u_decode_exact(&b64u_encode(&[1; 31]), 32).is_err());
    }
    #[test] fn wrong_kty_crv_or_missing_member_is_format_error() {
        let mut m = ec_public_members(&key().public_key());
        m.insert("crv".into(), "P-384".into());
        assert!(matches!(parse_ec_public(&m), Err(Error::Format(_))));
        let mut m = ec_public_members(&key().public_key()); m.remove("y");
        assert!(matches!(parse_ec_public(&m), Err(Error::Format(_))));
        let mut m = ec_public_members(&key().public_key()); m.insert("x".into(), 5.into());
        assert!(matches!(parse_ec_public(&m), Err(Error::Format(_))));
    }
}
