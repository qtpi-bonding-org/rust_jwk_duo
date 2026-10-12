//! Port of dart_jwk_duo lib/src/hex_codec.dart.
use crate::error::{format, Result};

pub struct HexCodec;

impl HexCodec {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// `expected_len` is a character count. Uppercase input is accepted.
    pub fn decode(hex: &str, expected_len: usize) -> Result<Vec<u8>> {
        if hex.len() != expected_len {
            return Err(format(format!("Hex must be exactly {expected_len} characters (got {})", hex.len())));
        }
        if expected_len % 2 == 1 {
            return Err(format(format!("Hex length must be even (got {expected_len})")));
        }
        if !hex.bytes().all(|c| c.is_ascii_hexdigit()) {
            return Err(format("Hex contains non-hexadecimal characters"));
        }
        Ok((0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("validated")).collect())
    }
}
#[cfg(test)]
mod tests {
    use super::HexCodec;
    use crate::Error;
    #[test] fn encode_produces_lowercase_zero_padded_hex() { assert_eq!(HexCodec::encode(&[0x00, 0x0a, 0xff]), "000aff"); }
    #[test] fn encode_and_decode_round_trip() {
        let bytes: Vec<u8> = (0u8..=255).collect();
        let hex = HexCodec::encode(&bytes);
        assert_eq!(HexCodec::decode(&hex, hex.len()).unwrap(), bytes);
    }
    #[test] fn decode_accepts_uppercase_hex() { assert_eq!(HexCodec::decode("0AFF", 4).unwrap(), vec![0x0a, 0xff]); }
    #[test] fn decode_rejects_wrong_length_odd_length_and_non_hex_in_that_order() {
        assert!(matches!(HexCodec::decode("00", 4), Err(Error::Format(m)) if m.contains("exactly 4")));
        assert!(matches!(HexCodec::decode("000", 3), Err(Error::Format(m)) if m.contains("even")));
        assert!(matches!(HexCodec::decode("0g", 2), Err(Error::Format(m)) if m.contains("non-hexadecimal")));
    }
}
