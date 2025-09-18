mod lib;
mod routes;

use actix_web::{App, HttpServer, web};
use crate::lib::generate_rsa_key;
use crate::routes::{jwks_handler, auth_handler, KeyStore};
use std::sync::{Arc, RwLock};
use env_logger::Env;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
    // Create a small set of keys: some unexpired, some expired for testing.
    let mut keys = Vec::new();

    // key with 1 hour TTL (unexpired)
    keys.push(generate_rsa_key(3600));

    // key with long TTL
    keys.push(generate_rsa_key(24 * 3600));

    // expired key: ttl = -3600 (expired 1 hour ago)
    keys.push(generate_rsa_key(-3600));

    let store: KeyStore = Arc::new(RwLock::new(keys));
    let data = web::Data::new(store);

    println!("Serving JWKS server on 127.0.0.1:8080");
    HttpServer::new(move || {
        App::new()
            .app_data(data.clone())
            .service(jwks_handler)
            .service(auth_handler)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
