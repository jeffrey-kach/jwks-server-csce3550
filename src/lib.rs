use chrono::{DateTime, Duration, Utc};
use openssl::rsa::Rsa;
use openssl::pkey::PKey;
use openssl::bn::BigNum;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::Serialize;
use jsonwebtoken::{EncodingKey, Header};
use rand::Rng;
use std::sync::Arc;

/// A stored key: contains private PEM, kid, and expiry time.
pub struct KeyEntry {
    pub kid: String,
    pub private_pem: Vec<u8>, // PKCS#1 PEM
    pub public_n: String,     // base64url mod
    pub public_e: String,     // base64url exp
    pub expires_at: DateTime<Utc>,
}

#[derive(Serialize)]
struct Jwk {
    kty: &'static str,
    n: String,
    e: String,
    alg: &'static str,
    kid: String,
    use_field: &'static str,
}

/// Generate an RSA keypair and return a KeyEntry with given TTL seconds.
pub fn generate_rsa_key(ttl_secs: i64) -> KeyEntry {
    // Generate 2048-bit RSA key
    let rsa = Rsa::generate(2048).expect("RSA generation failed");
    let private_pem = rsa.private_key_to_pem().expect("PEM export failed");
    // Get n and e
    let n_bn = rsa.n();
    let e_bn = rsa.e();

    // Convert BigNum to bytes (big-endian)
    let n_bytes = n_bn.to_vec();
    let e_bytes = e_bn.to_vec();

    let n_b64 = URL_SAFE_NO_PAD.encode(n_bytes);
    let e_b64 = URL_SAFE_NO_PAD.encode(e_bytes);

    let mut rng = rand::thread_rng();
    let kid: String = (0..8).map(|_| {
        let c = rng.gen_range(0..36);
        std::char::from_digit(c as u32, 36).unwrap()
    }).collect();

    KeyEntry {
        kid,
        private_pem,
        public_n: n_b64,
        public_e: e_b64,
        expires_at: Utc::now() + Duration::seconds(ttl_secs),
    }
}

/// Convert a KeyEntry to a public JWK representation
pub fn jwk_from_entry(e: &KeyEntry) -> Jwk {
    Jwk {
        kty: "RSA",
        n: e.public_n.clone(),
        e: e.public_e.clone(),
        alg: "RS256",
        kid: e.kid.clone(),
        use_field: "sig",
    }
}

/// Sign a payload (claims as JSON string) using the KeyEntry private PEM.
/// `additional_header` lets us inject the kid into JWT header.
pub fn sign_jwt_with_key(claims_json: &str, key: &KeyEntry, ttl_seconds_claim: i64) -> Result<String, jsonwebtoken::errors::Error> {
    // Build header with kid
    let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some(key.kid.clone());

    // The encoding key from PEM
    let enc_key = EncodingKey::from_rsa_pem(&key.private_pem)?;

    // We'll accept `claims_json` already a compact JSON; jsonwebtoken accepts claims as serde_json::Value
    let claims_value: serde_json::Value = serde_json::from_str(claims_json).unwrap_or(serde_json::json!({}));

    // convert back to map with maybe adding exp
    let mut map = claims_value.as_object().cloned().unwrap_or_default();
    // set exp to given TTL seconds relative to now (if provided)
    let exp = (Utc::now() + Duration::seconds(ttl_seconds_claim)).timestamp();
    map.insert("exp".to_string(), serde_json::json!(exp));
    let map_value = serde_json::Value::Object(map);

    // jsonwebtoken's encode accepts serde_json::Value with header
    let token = jsonwebtoken::encode(&header, &map_value, &enc_key)?;
    Ok(token)
}
