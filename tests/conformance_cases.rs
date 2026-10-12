//! Task 17: runs every `conformance/jwk_duo/*.json` case file through the public API.
//! The op table is `conformance/README.md`; the Dart runner reads the same files.
use base64ct::{Base64, Encoding};
use rust_jwk_duo::constants::FORMAT_VERSION;
use rust_jwk_duo::{
    calculate_jwk_thumbprint, Error, HexCodec, KeyDuoSerializer, PublicKeyDuo, Sec1PublicKey, SigningKeyPair,
    SigningPublicKeyHex, SymmetricKey, CryptoService,
};
use serde_json::{json, Value};

/// Exact case counts per file, so a truncated or silently emptied file fails.
const FILES: &[(&str, usize)] = &[
    ("hex", 8),
    ("sec1", 9),
    ("public_key_duo", 10),
    ("thumbprint", 11),
    ("jwk_set_valid", 4),
    ("jwk_set_invalid", 35),
    ("exported_jwk", 8),
    ("signature_verify", 10),
    ("hpke_open", 19),
    ("symmetric_open", 16),
];

fn dir() -> String {
    std::env::var("JWK_DUO_CONFORMANCE_DIR").unwrap_or_else(|_| concat!(env!("CARGO_MANIFEST_DIR"), "/conformance").to_string())
}

fn s<'a>(input: &'a Value, k: &str) -> &'a str {
    input[k].as_str().unwrap_or_else(|| panic!("input member {k} must be a string"))
}
fn b64(input: &Value, k: &str) -> Vec<u8> { Base64::decode_vec(s(input, k)).unwrap_or_else(|_| panic!("input member {k} is not base64")) }
fn hex(v: &str) -> Vec<u8> { HexCodec::decode(v, v.len()).expect("fixture hex") }
fn obj(input: &Value, k: &str) -> serde_json::Map<String, Value> { input[k].as_object().unwrap_or_else(|| panic!("input member {k} must be an object")).clone() }

fn run_op(op: &str, input: &Value) -> Result<Value, Error> {
    Ok(match op {
        "hex.decode" => {
            let len = input["expected_len"].as_u64().expect("expected_len") as usize;
            json!(HexCodec::encode(&HexCodec::decode(s(input, "hex"), len)?))
        }
        "hex.encode" => {
            let h = s(input, "bytes_hex");
            json!(HexCodec::encode(&HexCodec::decode(h, h.len())?))
        }
        "sec1.decode_hex" => json!(HexCodec::encode(&Sec1PublicKey::decode_hex(s(input, "hex"))?)),
        "public_key_duo.from_json" => PublicKeyDuo::from_json(&input["json"])?.to_json(),
        "thumbprint" => json!(calculate_jwk_thumbprint(&obj(input, "jwk"))?),
        "jwk_set.import_private" => KeyDuoSerializer::import_key_duo_jwk(s(input, "jwk_set"))?.export_public_key_duo().to_json(),
        "jwk_set.import_public" => KeyDuoSerializer::import_public_key_duo_jwk(s(input, "jwk_set"))?.export_public_key_duo().to_json(),
        "exported_jwk.check" => {
            rust_jwk_duo::__exported_jwk_check(s(input, "alg"), s(input, "use"))?;
            json!(true)
        }
        "signature.verify" => {
            let key = SigningKeyPair::import_public_key_sec1_hex(&SigningPublicKeyHex::new(s(input, "public_hex"))?)?;
            json!(key.verify_bytes(&hex(s(input, "signature_hex")), &b64(input, "message_b64")))
        }
        "crypto.decrypt" => {
            let duo = KeyDuoSerializer::import_key_duo_jwk(s(input, "jwk_set"))?;
            let pt = CryptoService::decrypt(&b64(input, "blob_b64"), duo.encryption_key_pair(), &b64(input, "info_b64"), &b64(input, "aad_b64"))?;
            json!(Base64::encode_string(&pt))
        }
        "symmetric.decrypt" => {
            let key = SymmetricKey::from_jwk(s(input, "key_jwk"))?;
            json!(Base64::encode_string(&CryptoService::decrypt_symmetric(&b64(input, "blob_b64"), &key, &b64(input, "aad_b64"))?))
        }
        other => panic!("unknown op {other}"),
    })
}

fn kind(e: &Error) -> &'static str {
    match e { Error::Format(_) => "format", Error::State(_) => "state", Error::Argument(_) => "argument" }
}

fn run_file(name: &str, want_cases: usize) {
    let path = format!("{}/jwk_duo/{name}.json", dir());
    let doc: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"))).expect("case file is JSON");
    assert_eq!(doc["format_version"], json!(FORMAT_VERSION), "{name}: format_version");
    let cases = doc["cases"].as_array().unwrap_or_else(|| panic!("{name}: cases must be an array"));
    assert_eq!(cases.len(), want_cases, "{name}: case count (truncated or extended file)");
    let mut ids = std::collections::HashSet::new();
    for c in cases {
        let id = c["id"].as_str().expect("case id");
        assert!(ids.insert(id), "{name}: duplicate id {id}");
        let op = c["op"].as_str().or(doc["op"].as_str()).unwrap_or_else(|| panic!("{name}/{id}: no op"));
        let got = run_op(op, &c["input"]);
        let expect = c["expect"].as_object().unwrap_or_else(|| panic!("{name}/{id}: expect must be an object"));
        assert_eq!(expect.len(), 1, "{name}/{id}: expect has exactly one member");
        match (expect.get("ok"), expect.get("error")) {
            (Some(want), None) => match got {
                Ok(v) => assert_eq!(&v, want, "{name}/{id} ({op})"),
                Err(e) => panic!("{name}/{id} ({op}): expected ok, got {e:?}"),
            },
            (None, Some(Value::String(k))) => match got {
                Ok(v) => panic!("{name}/{id} ({op}): expected error {k}, got ok {v}"),
                Err(e) => assert_eq!(kind(&e), k, "{name}/{id} ({op}): {e:?}"),
            },
            _ => panic!("{name}/{id}: expect must be {{ok}} or {{error}}"),
        }
    }
}

macro_rules! file_test {
    ($($fn_name:ident => $file:literal),* $(,)?) => {$(
        #[test] fn $fn_name() {
            let want = FILES.iter().find(|(n, _)| *n == $file).expect("file listed in FILES").1;
            run_file($file, want);
        }
    )*};
}
file_test! {
    hex_cases => "hex", sec1_cases => "sec1", public_key_duo_cases => "public_key_duo", thumbprint_cases => "thumbprint",
    jwk_set_valid_cases => "jwk_set_valid", jwk_set_invalid_cases => "jwk_set_invalid", exported_jwk_cases => "exported_jwk",
    signature_verify_cases => "signature_verify", hpke_open_cases => "hpke_open", symmetric_open_cases => "symmetric_open",
}

/// No case file may be left unrun, and none may be missing.
#[test] fn every_case_file_is_wired() {
    let mut on_disk: Vec<String> = std::fs::read_dir(format!("{}/jwk_duo", dir())).expect("jwk_duo dir").map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| n.ends_with(".json")).map(|n| n.trim_end_matches(".json").to_string()).collect();
    on_disk.sort();
    let mut listed: Vec<String> = FILES.iter().map(|(n, _)| n.to_string()).collect();
    listed.sort();
    assert_eq!(on_disk, listed);
}
