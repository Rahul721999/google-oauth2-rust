use actix_web::{HttpResponse, web};
use dotenv::dotenv;
use oauth2::{
    basic::BasicClient, AuthUrl, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge, RedirectUrl,
    Scope, TokenUrl, AuthorizationCode, reqwest::async_http_client,
};
use std::env;

pub async fn google_auth() -> Result<HttpResponse, actix_web::Error> {
    dotenv().ok();
    // get the clientID from env
    let google_client_id = ClientId::new(
        env::var("GOOGLE_CLIENT_ID").expect("Missing the GOOGLE_CLIENT_ID environment variable."),
    );

    // get the google secret
    let google_client_secret = ClientSecret::new(
        env::var("GOOGLE_CLIENT_SECRET")
            .expect("Missing the GOOGLE_CLIENT_SECRET environment variable."),
    );

    let auth_url = AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string())
        .expect("Invalid authorization endpoint URL");
    let token_url = TokenUrl::new("https://www.googleapis.com/oauth2/v3/token".to_string())
        .expect("Invalid token endpoint URL");

    // setup the google oAuth2 process
    let client = BasicClient::new(
        google_client_id,
        Some(google_client_secret),
        auth_url,
        Some(token_url),
    )
    .set_redirect_uri(
        RedirectUrl::new("http://localhost:8080".to_string()).expect("failed to set redirect url"),
    );

    // Generate a PKCE challenge.
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    // Generate the full authorization URL.
    let (auth_url, _csrf_token) = client
        .authorize_url(CsrfToken::new_random)

        // Set the PKCE code challenge.
        .set_pkce_challenge(pkce_challenge)
        .url();
    println!("{}", auth_url);

    let token_result = client
    .exchange_code(AuthorizationCode::new("authorization_code".to_string()))
    // Set the PKCE code verifier.
    .set_pkce_verifier(pkce_verifier)
    .request_async(async_http_client)
    .await.expect("failed to get the token");
    println!("{:#?}",token_result);
    Ok(HttpResponse::Ok().body("Success"))
}


use serde::Deserialize;

#[derive(Deserialize)]
pub struct CallbackParams {
    code: String,
    state: String,
}

pub async fn callback_handler(params: web::Query<CallbackParams>) -> HttpResponse {
    // Extract the authorization code and state from the query parameters
    let code = &params.code;
    let state = &params.state;

    // Process the authorization code and state as needed
    // For example, exchange the authorization code for access token and refresh token

    // Return a response indicating successful authorization
    HttpResponse::Ok().body(format!("Authorization successful! Code: {}, State: {}", code, state))
}