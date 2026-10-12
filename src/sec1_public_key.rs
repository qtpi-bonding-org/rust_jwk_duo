//! Port of dart_jwk_duo lib/src/sec1_public_key.dart.
use crate::constants::crypto_sizes::*;
use crate::error::{format, Result};
use crate::HexCodec;
use p256::elliptic_curve::sec1::ToSec1Point;

pub struct Sec1PublicKey;

impl Sec1PublicKey {
    pub fn validate_raw(raw: &[u8]) -> Result<&[u8]> {
        if raw.len() != EC_P256_SEC1_PUBLIC_KEY_LENGTH {
            return Err(format(format!("SEC1 public key must be {EC_P256_SEC1_PUBLIC_KEY_LENGTH} bytes (got {})", raw.len())));
        }
        if raw[0] != SEC1_UNCOMPRESSED_TAG {
            return Err(format(format!("SEC1 public key must begin with the uncompressed tag 0x04 (got 0x{:02x})", raw[0])));
        }
        Ok(raw)
    }
    pub fn decode_hex(sec1_hex: &str) -> Result<Vec<u8>> {
        let raw = HexCodec::decode(sec1_hex, EC_P256_SEC1_PUBLIC_KEY_HEX_LENGTH)?;
        Self::validate_raw(&raw)?;
        Ok(raw)
    }
    pub fn encode_hex(raw: &[u8]) -> Result<String> {
        Ok(HexCodec::encode(Self::validate_raw(raw)?))
    }
    /// Structural check, then the library's on-curve check.
    pub fn import_p256(raw: &[u8]) -> Result<p256::PublicKey> {
        Self::validate_raw(raw)?;
        p256::PublicKey::from_sec1_bytes(raw).map_err(|_| format("SEC1 public key is not a valid P-256 point"))
    }
    pub fn export_p256(pk: &p256::PublicKey) -> [u8; 65] {
        let point = pk.to_sec1_point(false);
        let mut out = [0u8; 65];
        out.copy_from_slice(point.as_bytes());
        out
    }
}
#[cfg(test)]
mod tests {
    use super::Sec1PublicKey;
    use crate::Error;
    const BARE_128: &str = "aa"; // repeated below
    #[test] fn rejects_the_bare_128_hex_coordinate_form() {
        assert!(matches!(Sec1PublicKey::decode_hex(&BARE_128.repeat(64)), Err(Error::Format(_))));
    }
    #[test] fn rejects_wrong_length() {
        assert!(Sec1PublicKey::decode_hex(&"04".repeat(64)).is_err());
        assert!(Sec1PublicKey::validate_raw(&[0x04; 64]).is_err());
    }
    #[test] fn rejects_non_hex_characters() {
        let mut s = "04".to_string(); s.push_str(&"zz".repeat(64));
        assert!(matches!(Sec1PublicKey::decode_hex(&s), Err(Error::Format(_))));
    }
    #[test] fn rejects_130_hex_whose_tag_is_not_04() {
        let s = format!("03{}", "11".repeat(64));
        assert!(matches!(Sec1PublicKey::decode_hex(&s), Err(Error::Format(m)) if m.contains("uncompressed tag")));
    }
    #[test] fn well_encoded_point_not_on_curve_is_unimportable() {
        let mut raw = [0u8; 65]; raw[0] = 0x04; raw[1] = 1; raw[33] = 1; // (1,1) is not on P-256
        assert!(Sec1PublicKey::validate_raw(&raw).is_ok());
        assert!(matches!(Sec1PublicKey::import_p256(&raw), Err(Error::Format(_))));
    }
    #[test] fn compressed_points_are_rejected() {
        let mut raw = vec![0x02]; raw.extend([0x11; 32]);
        assert!(Sec1PublicKey::import_p256(&raw).is_err());
    }
}
