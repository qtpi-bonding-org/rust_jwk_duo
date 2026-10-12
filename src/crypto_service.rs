//! Port of dart_jwk_duo lib/src/crypto_service.dart. The old ECDH+HKDF+AES-GCM
//! recipe (crypto_service.dart:49-140, 241-253) is deleted; encryption to a
//! public key is HPKE (RFC 9180) via the `hpke` crate.
use crate::constants::{crypto_sizes::*, hpke as H};
use crate::error::{format, Result};
use crate::{EncryptionKeyPair, HexCodec, SigningKeyPair, SymmetricKey};
use aes_gcm::aead::{Aead, Payload};
use base64ct::{Base64, Encoding};
use hpke::{aead::AesGcm256, kdf::HkdfSha256, kem::DhP256HkdfSha256, Deserializable, Kem, OpModeR, OpModeS, Serializable};

pub struct CryptoService;

fn full_info(info: &[u8]) -> Vec<u8> { let mut v = H::INFO_PREFIX.to_vec(); v.extend_from_slice(info); v }
const DECRYPT_FAILED: &str = "Decryption failed: wrong key, info, aad, or tampered data";

impl CryptoService {
    pub fn encrypt(data: &[u8], recipient: &EncryptionKeyPair, info: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let (enc, ct) = hpke::single_shot_seal::<AesGcm256, HkdfSha256, DhP256HkdfSha256>(&OpModeS::Base, &recipient.hpke_public(), &full_info(info), data, aad)
            .map_err(|_| format("HPKE seal failed"))?;
        let mut out = Vec::with_capacity(H::HEADER_LENGTH + ct.len());
        out.push(H::VERSION_V1); out.extend_from_slice(&enc.to_bytes()); out.extend_from_slice(&ct);
        Ok(out)
    }
    pub fn decrypt(data: &[u8], recipient: &EncryptionKeyPair, info: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let sk = recipient.hpke_private()?; // State error first, as 2.x
        if data.len() < H::MIN_BLOB_LENGTH { return Err(format(format!("Encrypted data must be at least {} bytes (got {})", H::MIN_BLOB_LENGTH, data.len()))); }
        if data[0] != H::VERSION_V1 { return Err(format(format!("Unknown encryption format version 0x{:02x}", data[0]))); }
        let enc = <DhP256HkdfSha256 as Kem>::EncappedKey::from_bytes(&data[1..H::HEADER_LENGTH]).map_err(|_| format(DECRYPT_FAILED))?;
        hpke::single_shot_open::<AesGcm256, HkdfSha256, DhP256HkdfSha256>(&OpModeR::Base, &sk, &enc, &full_info(info), &data[H::HEADER_LENGTH..], aad)
            .map_err(|_| format(DECRYPT_FAILED))
    }
    pub fn sign(data: &[u8], signer: &SigningKeyPair) -> Result<[u8; 64]> { signer.sign_bytes(data) }
    pub fn verify_signature(data: &[u8], sig: &[u8], verifier: &SigningKeyPair) -> bool { verifier.verify_bytes(sig, data) }
    pub fn encrypt_symmetric(data: &[u8], key: &SymmetricKey, aad: &[u8]) -> Result<Vec<u8>> {
        let mut iv = [0u8; AES_GCM_IV_LENGTH]; getrandom::fill(&mut iv).expect("OS RNG unavailable");
        let ct = key.cipher().encrypt(&iv.into(), Payload { msg: data, aad }).map_err(|_| format("AES-GCM encryption failed"))?;
        let mut out = iv.to_vec(); out.extend(ct); Ok(out)
    }
    pub fn decrypt_symmetric(data: &[u8], key: &SymmetricKey, aad: &[u8]) -> Result<Vec<u8>> {
        let min = AES_GCM_IV_LENGTH + AES_GCM_TAG_LENGTH;
        if data.len() < min { return Err(format(format!("Encrypted data must be at least {min} bytes (got {})", data.len()))); }
        let iv: [u8; AES_GCM_IV_LENGTH] = data[..AES_GCM_IV_LENGTH].try_into().expect("length checked");
        key.cipher().decrypt(&iv.into(), Payload { msg: &data[AES_GCM_IV_LENGTH..], aad }).map_err(|_| format(DECRYPT_FAILED))
    }
    pub fn encrypt_string(s: &str, r: &EncryptionKeyPair, info: &[u8], aad: &[u8]) -> Result<String> { Ok(Base64::encode_string(&Self::encrypt(s.as_bytes(), r, info, aad)?)) }
    pub fn decrypt_string(b64: &str, r: &EncryptionKeyPair, info: &[u8], aad: &[u8]) -> Result<String> {
        let bytes = Base64::decode_vec(b64).map_err(|_| format("Invalid base64"))?;
        String::from_utf8(Self::decrypt(&bytes, r, info, aad)?).map_err(|_| format("Decrypted data is not UTF-8"))
    }
    pub fn sign_string(s: &str, signer: &SigningKeyPair) -> Result<String> { Ok(HexCodec::encode(&Self::sign(s.as_bytes(), signer)?)) }
    pub fn verify_signature_string(s: &str, sig_hex: &str, v: &SigningKeyPair) -> Result<bool> {
        let sig = HexCodec::decode(sig_hex, ECDSA_P256_SIGNATURE_LENGTH * 2)?;
        Ok(Self::verify_signature(s.as_bytes(), &sig, v))
    }
}
#[cfg(test)]
mod tests {
    use super::CryptoService as C; use crate::*;
    fn kp() -> EncryptionKeyPair { EncryptionKeyPair::generate() }
    #[test] fn hpke_layout_is_version_enc_ct_tag() {
        let k = kp(); let b = C::encrypt(b"abc", &k, b"", b"").unwrap();
        assert_eq!(b[0], 0x01); assert_eq!(b.len(), 1 + 65 + 3 + 16); assert_eq!(b[1], 0x04);
    }
    #[test] fn round_trip_empty_small_large_and_public_only_sender() {
        let k = kp(); let pubonly = EncryptionKeyPair::import_public_key_raw(&crate::interfaces::KeyPair::export_public_key_raw(&k)).unwrap();
        for n in [0usize, 1, 100_000] { let m = vec![7u8; n]; let b = C::encrypt(&m, &pubonly, b"i", b"a").unwrap(); assert_eq!(C::decrypt(&b, &k, b"i", b"a").unwrap(), m); }
        assert!(matches!(C::decrypt(&C::encrypt(b"x", &k, b"", b"").unwrap(), &pubonly, b"", b""), Err(Error::State(_))));
    }
    #[test] fn fresh_ephemeral_each_time() { let k = kp(); assert_ne!(C::encrypt(b"x", &k, b"", b"").unwrap()[1..66], C::encrypt(b"x", &k, b"", b"").unwrap()[1..66]); }
    #[test] fn hpke_rejects_wrong_info_aad_version_tamper_truncation_and_other_recipient() {
        let k = kp(); let b = C::encrypt(b"secret", &k, b"info", b"aad").unwrap();
        assert_eq!(C::decrypt(&b, &k, b"info", b"aad").unwrap(), b"secret"); // positive control
        assert!(matches!(C::decrypt(&b, &k, b"other", b"aad"), Err(Error::Format(_))));
        assert!(matches!(C::decrypt(&b, &k, b"info", b"other"), Err(Error::Format(_))));
        let mut v = b.clone(); v[0] = 0x02; assert!(matches!(C::decrypt(&v, &k, b"info", b"aad"), Err(Error::Format(_))));
        for i in [1usize, 40, 70, b.len() - 1] { let mut t = b.clone(); t[i] ^= 1; assert!(C::decrypt(&t, &k, b"info", b"aad").is_err()); }
        assert!(matches!(C::decrypt(&b[..81], &k, b"info", b"aad"), Err(Error::Format(_))));
        for n in [0usize, 1, 2, 65, 66, 80] { assert!(matches!(C::decrypt(&b[..n], &k, b"info", b"aad"), Err(Error::Format(_)))); } // short input: Format, never a panic
        let mut longer = b.clone(); longer.push(0); assert!(C::decrypt(&longer, &k, b"info", b"aad").is_err());
        assert!(C::decrypt(&b, &kp(), b"info", b"aad").is_err());
    }
    #[test] fn symmetric_layout_and_truncation() {
        let s = SymmetricKey::generate(); let b = C::encrypt_symmetric(b"abc", &s, b"").unwrap();
        assert_eq!(b.len(), 12 + 3 + 16); assert_eq!(C::decrypt_symmetric(&b, &s, b"").unwrap(), b"abc");
        assert!(matches!(C::decrypt_symmetric(&b[..27], &s, b""), Err(Error::Format(_))));
        assert!(C::decrypt_symmetric(&b, &s, b"wrong aad").is_err());
    }
    #[test] fn string_helpers_round_trip_and_hex_length_is_checked() {
        let k = kp(); let s = SigningKeyPair::generate();
        let c = C::encrypt_string("héllo", &k, b"", b"").unwrap(); assert_eq!(C::decrypt_string(&c, &k, b"", b"").unwrap(), "héllo");
        let sig = C::sign_string("m", &s).unwrap(); assert_eq!(sig.len(), 128); assert!(C::verify_signature_string("m", &sig, &s).unwrap());
        assert!(matches!(C::verify_signature_string("m", "abcd", &s), Err(Error::Format(_))));
    }
}
