use actix_web::{web, HttpResponse, Responder, post, get, HttpRequest};
use crate::lib::{KeyEntry, jwk_from_entry, sign_jwt_with_key};
use serde::Serialize;
use chrono::Utc;
use std::sync::{Arc, RwLock};

#[derive(Serialize)]
struct Jwks {
    keys: Vec<serde_json::Value>,
}

/// Shared app state
pub type KeyStore = Arc<RwLock<Vec<KeyEntry>>>;

/// GET /jwks - returns only unexpired public keys
#[get("/jwks")]
pub async fn jwks_handler(state: web::Data<KeyStore>) -> impl Responder {
    let guard = state.read().unwrap();
    let now = Utc::now();
    let keys: Vec<_> = guard.iter()
        .filter(|k| k.expires_at > now)
        .map(|k| serde_json::to_value(jwk_from_entry(k)).unwrap())
        .collect();
    let jwks = Jwks { keys };
    HttpResponse::Ok().json(jwks)
}

/// POST /auth - mock authentication; returns signed JWT.
/// Query: ?expired=true -> sign with first expired key (if any)
#[post("/auth")]
pub async fn auth_handler(req: HttpRequest, state: web::Data<KeyStore>) -> impl Responder {
    let query = req.query_string();
    let use_expired = req.uri().query().map_or(false, |q| q.contains("expired=true"));

    let guard = state.read().unwrap();
    // choose key based on query
    let now = Utc::now();

    let maybe_key = if use_expired {
        // find an expired key
        guard.iter().find(|k| k.expires_at <= now).cloned()
    } else {
        // find a non-expired key
        guard.iter().find(|k| k.expires_at > now).cloned()
    };

    if let Some(key) = maybe_key {
        // Create some fake claims
        let claims = serde_json::json!({
            "sub": "test-user",
            "iat": Utc::now().timestamp()
        }).to_string();

        // If signing with an expired key (per requirements), set token exp to key.expires_at
        let ttl_claim_seconds = if use_expired {
            // set exp to key.expires_at - now (seconds, could be negative)
            (key.expires_at.timestamp() - Utc::now().timestamp())
        } else {
            // token valid for 3600 seconds by default
            3600
        };

        match sign_jwt_with_key(&claims, &key, ttl_claim_seconds) {
            Ok(token) => HttpResponse::Ok().json(serde_json::json!({ "token": token })),
            Err(e) => {
                HttpResponse::InternalServerError().body(format!("failed to sign: {}", e))
            }
        }
    } else {
        HttpResponse::NotFound().body("no suitable key")
    }
}
