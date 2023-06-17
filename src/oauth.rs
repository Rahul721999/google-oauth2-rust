#![allow(unused)]
use actix_web::{HttpResponse, web};
use dotenv::dotenv;
use oauth2::{
    CsrfToken, PkceCodeChallenge, RedirectUrl,
    Scope, AuthorizationCode, reqwest::{async_http_client, http_client}, StandardRevocableToken, TokenResponse, PkceCodeVerifier, RevocationUrl,
};
use url::Url;
use std::{net::TcpListener, io::{Write, BufReader, BufRead}, collections::HashMap, sync::{Arc, Mutex}};
use serde_json::json;
use crate::get_client::get;
use crate::PkceVerifier;


/// 
/// API to get the Authentication Url from google
/// 
pub async fn google_auth_url( data: web::Data<Arc<Mutex<PkceVerifier>>>) -> Result<HttpResponse, actix_web::Error> {
    dotenv().ok();
    let mut lock = data.lock().expect("failed to get the Mutex value");
    // get the clientID 
    let client = get().set_redirect_uri(
        RedirectUrl::new("http://localhost:8080/callback".to_string()).expect("failed to set redirect url")
    );

    // Generate a PKCE challenge.
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    lock.value = pkce_verifier.secret().to_string();
    println!("pkce_verifier:{}",lock.value);
    // Generate the full authorization URL.
    let (auth_url, csrf_token) = client
        .authorize_url(CsrfToken::new_random)
        // Set the PKCE code challenge.
        .add_scope(Scope::new(
            "https://www.googleapis.com/auth/userinfo.profile".to_string(),
        ))
        .add_scope(Scope::new(
            "https://www.googleapis.com/auth/plus.me".to_string(),
        ))
        .set_pkce_challenge(pkce_challenge)
        .url();
    // Create the authorization URL with the PKCE verifier
    println!("{}", auth_url);

    Ok(HttpResponse::Ok().json(json!({
        "auth_url": auth_url,
        "pkce_verifier": pkce_verifier.secret()
    })))
}


///
///  callback Api get's redirected when Authentication gets successful  
/// 
pub async fn auth_callback(query_params: web::Query<HashMap<String, String>>, data: web::Data<Arc<Mutex<PkceVerifier>>>) -> HttpResponse{

    // Extract the authorization code from the query parameters
    let code = query_params
        .get("code")
        .ok_or_else(|| HttpResponse::BadRequest().body("Missing authorization code")).expect("failed to get the code from query param");
    
    // get teh PkceVerifier from ARC<Mutex>...
    let mut lock = data.lock().expect("failed to get the Mutex value");
    println!("pkce_verifier: {}",lock.value);
    let pkce_verifier = PkceCodeVerifier::new(lock.value.clone());

    // Generate the client and 
    let client = get().set_revocation_uri(
        RevocationUrl::new("https://oauth2.googleapis.com/revoke".to_string())
            .expect("Invalid revocation endpoint URL"),
    );
    let token_response = client.clone()
    .set_redirect_uri(RedirectUrl::new("http://localhost:8080/callback".to_owned()).expect("failed to get url"))
    .exchange_code(AuthorizationCode::new(code.to_owned()))
    .set_pkce_verifier(pkce_verifier)
    .request_async(async_http_client).await.expect("failed to get the token");



    // revoke token..
    let token_to_revoke: StandardRevocableToken = token_response.access_token().into();
    println!("{:?}",token_to_revoke);

    let res = client
    .set_redirect_uri(RedirectUrl::new("https://accounts.google.com/o/oauth2/revoke".to_owned()).expect("failed to get url"))
    .revoke_token(token_to_revoke)
    .unwrap()
    .request_async(async_http_client).await.expect("failed to revoke token");
    
    HttpResponse::Ok().body(format!("{}",token_response.access_token().secret()))
}