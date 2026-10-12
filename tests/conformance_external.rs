//! Task 16: external vectors (Wycheproof, RFC 9180, JOSE-HPKE A.13).
use hpke::{aead::AesGcm256, kdf::HkdfSha256, kem::DhP256HkdfSha256, Deserializable, Kem, OpModeR};
use rust_jwk_duo::crypto_service::__seal_with_ikm_e_for_tests;
use rust_jwk_duo::{calculate_jwk_thumbprint, CryptoService, EncryptionKeyPair, SigningKeyPair};
use serde_json::Value;

fn dir() -> String {
    std::env::var("JWK_DUO_CONFORMANCE_DIR").unwrap_or_else(|_| concat!(env!("CARGO_MANIFEST_DIR"), "/conformance").to_string())
}
fn load(rel: &str) -> Value { serde_json::from_str(&std::fs::read_to_string(format!("{}/{rel}", dir())).unwrap()).unwrap() }
fn h(v: &Value) -> Vec<u8> { hex::decode(v.as_str().unwrap()).unwrap() }
fn tests(d: &Value) -> impl Iterator<Item = (&Value, &Value)> {
    d["testGroups"].as_array().unwrap().iter().flat_map(|g| g["tests"].as_array().unwrap().iter().map(move |t| (g, t)))
}

fn ecdsa_p1363_case() -> (usize, usize) {
    let d = load("wycheproof/ecdsa_secp256r1_sha256_p1363_test.json");
    let (mut n, mut imp_fail) = (0, 0);
    for g in d["testGroups"].as_array().unwrap() {
        let kp = SigningKeyPair::import_public_key_raw(&h(&g["publicKey"]["uncompressed"]));
        for t in g["tests"].as_array().unwrap() {
            let verdict = match &kp {
                Ok(k) => k.verify_bytes(&h(&t["sig"]), &h(&t["msg"])),
                Err(_) => { imp_fail += 1; assert_eq!(t["result"], "invalid", "tc {}", t["tcId"]); false }
            };
            assert_eq!(verdict, t["result"] == "valid", "tc {} {}", t["tcId"], t["comment"]);
            n += 1;
        }
    }
    (n, imp_fail)
}

#[test] fn wycheproof_ecdsa_p1363() { let (n, _) = ecdsa_p1363_case(); assert_eq!(n, 262); }

#[test] fn wycheproof_ecdsa_der() {
    let d = load("wycheproof/ecdsa_secp256r1_sha256_test.json");
    let mut n = 0;
    for g in d["testGroups"].as_array().unwrap() {
        let kp = SigningKeyPair::import_public_key_raw(&h(&g["publicKey"]["uncompressed"]));
        for t in g["tests"].as_array().unwrap() {
            let verdict = match (&kp, SigningKeyPair::signature_from_der(&h(&t["sig"]))) {
                (Ok(k), Ok(s)) => k.verify_bytes(&s, &h(&t["msg"])),
                _ => false,
            };
            assert_eq!(verdict, t["result"] == "valid", "tc {} {}", t["tcId"], t["comment"]);
            n += 1;
        }
    }
    assert_eq!(n, 484);
}

#[test] fn wycheproof_ecdh_ecpoint_import_outcome() {
    let d = load("wycheproof/ecdh_secp256r1_ecpoint_test.json");
    let mut n = 0;
    for (_, t) in tests(&d) {
        let r = EncryptionKeyPair::import_public_key_raw(&h(&t["public"]));
        assert_eq!(r.is_ok(), t["result"] == "valid", "tc {} {}", t["tcId"], t["comment"]);
        n += 1;
    }
    assert_eq!(n, 355);
}

#[test] fn wycheproof_ecdh_webcrypto_jwk_import() {
    let d = load("wycheproof/ecdh_secp256r1_webcrypto_test.json");
    let mut n = 0;
    for (_, t) in tests(&d) {
        let r = rust_jwk_duo::__parse_ec_public_jwk(&t["public"].to_string());
        assert_eq!(r.is_ok(), t["result"] == "valid", "tc {} {}: {:?}", t["tcId"], t["comment"], r);
        n += 1;
    }
    assert_eq!(n, 353);
}

#[test] fn wycheproof_aes_gcm_256_96_128() {
    let d = load("wycheproof/aes_gcm_test.json");
    let (mut n, mut valid) = (0, 0);
    for g in d["testGroups"].as_array().unwrap() {
        if !(g["keySize"] == 256 && g["ivSize"] == 96 && g["tagSize"] == 128) { continue; }
        for t in g["tests"].as_array().unwrap() {
            let key: [u8; 32] = h(&t["key"]).try_into().unwrap();
            let sk = rust_jwk_duo::__symmetric_from_raw(&key);
            let mut blob = h(&t["iv"]); blob.extend(h(&t["ct"])); blob.extend(h(&t["tag"]));
            let r = CryptoService::decrypt_symmetric(&blob, &sk, &h(&t["aad"]));
            if t["result"] == "valid" { assert_eq!(r.unwrap(), h(&t["msg"]), "tc {}", t["tcId"]); valid += 1; }
            else { assert!(r.is_err(), "tc {} {}", t["tcId"], t["comment"]); }
            n += 1;
        }
    }
    assert!(n > 0 && valid > 0, "filter selected nothing");
    println!("aes_gcm 256/96/128: {n} cases, {valid} valid");
}

#[test] fn rfc9180_open_and_seal() {
    let v = &load("rfc9180/test-vectors.json")[0];
    assert_eq!((&v["mode"], &v["kem_id"], &v["kdf_id"], &v["aead_id"]), (&Value::from(0), &Value::from(16), &Value::from(1), &Value::from(2)));
    let (sk_rm, enc, info, pk_rm, ikm_e) = (h(&v["skRm"]), h(&v["enc"]), h(&v["info"]), h(&v["pkRm"]), h(&v["ikmE"]));
    let sk = <DhP256HkdfSha256 as Kem>::PrivateKey::from_bytes(&sk_rm).unwrap();
    let encapped = <DhP256HkdfSha256 as Kem>::EncappedKey::from_bytes(&enc).unwrap();
    let encs = v["encryptions"].as_array().unwrap();
    // Open: encryption 0 single-shot.
    let e0 = &encs[0];
    let ct0 = [h(&e0["ct"])].concat();
    assert_eq!(hpke::single_shot_open::<AesGcm256, HkdfSha256, DhP256HkdfSha256>(&OpModeR::Base, &sk, &encapped, &info, &ct0, &h(&e0["aad"])).unwrap(), h(&e0["pt"]));
    // Open: every encryption, in sequence, through one receiver context.
    let mut ctx = hpke::setup_receiver::<AesGcm256, HkdfSha256, DhP256HkdfSha256>(&OpModeR::Base, &sk, &encapped, &info).unwrap();
    for (i, e) in encs.iter().enumerate() {
        assert_eq!(ctx.open(&h(&e["ct"]), &h(&e["aad"])).unwrap(), h(&e["pt"]), "encryption {i}");
    }
    // Seal: reproduce enc and ct byte for byte from ikmE.
    let (got_enc, got_ct) = __seal_with_ikm_e_for_tests(&pk_rm, &info, &h(&e0["pt"]), &h(&e0["aad"]), &ikm_e);
    assert_eq!(got_enc, enc);
    assert_eq!(got_ct, h(&e0["ct"]));
    println!("rfc9180 encryptions: {}", encs.len());
}

#[test] fn jose_a13_thumbprint_and_private_import() {
    let j = load("jose_hpke/a13_hpke7_private_jwk.json");
    assert_eq!(calculate_jwk_thumbprint(j.as_object().unwrap()).unwrap(), j["kid"].as_str().unwrap());
    rust_jwk_duo::__parse_ec_private_jwk(&j.to_string()).unwrap();
}
