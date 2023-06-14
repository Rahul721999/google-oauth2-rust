use oauth2::{
    basic::BasicClient, AuthUrl, ClientId, ClientSecret, TokenUrl,
};
use std::env;
use dotenv::dotenv;
pub fn get()-> BasicClient{
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
    BasicClient::new(google_client_id, Some(google_client_secret), auth_url, Some(token_url))
}