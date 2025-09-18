use actix_web::{test, App};
use jwks_server::routes::{jwks_handler, auth_handler, KeyStore};
use jwks_server::lib::generate_rsa_key;
use std::sync::{Arc, RwLock};

#[actix_rt::test]
async fn test_jwks_only_unexpired() {
    // Setup store: one unexpired and one expired
    let mut k = Vec::new();
    k.push(generate_rsa_key(3600));  // unexpired
    k.push(generate_rsa_key(-3600)); // expired
    let store: KeyStore = Arc::new(RwLock::new(k));
    let app = test::init_service(
        App::new()
        .app_data(actix_web::web::Data::new(store))
        .service(jwks_handler)
    ).await;

    let req = test::TestRequest::get().uri("/jwks").to_request();
    let resp = test::call_and_read_body_json(&app, req).await;
    // jwks should have only 1 key
    assert!(resp.get("keys").unwrap().as_array().unwrap().len() == 1);
}

#[actix_rt::test]
async fn test_auth_returns_token_and_kid_header() {
    let mut k = Vec::new();
    k.push(generate_rsa_key(3600));  // unexpired
    k.push(generate_rsa_key(-3600)); // expired
    let store: KeyStore = Arc::new(RwLock::new(k));
    let app = test::init_service(
        App::new()
        .app_data(actix_web::web::Data::new(store.clone()))
        .service(auth_handler)
    ).await;

    // request non-expired token
    let req = test::TestRequest::post().uri("/auth").to_request();
    let resp_body: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    let token = resp_body.get("token").unwrap().as_str().unwrap();
    // ensure token has a kid in header
    let header = jsonwebtoken::decode_header(token).unwrap();
    assert!(header.kid.is_some());
}
