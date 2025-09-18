# JWKS Server (Rust + Actix)

This is a basic **JWKS server** written in Rust.  
It generates RSA key pairs with expiry, serves public keys in JWKS format, and issues JWTs from an `/auth` endpoint.

## Features
- `/jwks` → returns JSON Web Key Set (only unexpired keys)
- `/auth` → issues JWT signed with an unexpired key
- `/auth?expired=true` → issues JWT signed with an expired key (for testing)

## Run
```bash
cargo run
