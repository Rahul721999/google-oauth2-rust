use actix_web::{web, HttpResponse, Responder, HttpServer, App};
use std::sync::{Arc, Mutex};
mod oauth;
mod utils;
use serde::{Serialize, Deserialize};
pub use utils::get_client;
use oauth::{google_auth_url, auth_callback};

#[derive(Serialize, Deserialize)]
pub struct PkceVerifier{
    value: String
}



async fn healthcheck() -> impl Responder {
    HttpResponse::Ok().body("health check success")
}


#[actix_web::main]
async fn main() -> std::io::Result<()> {

    let db = Arc::new(Mutex::new(PkceVerifier{value: "".to_string()}));

    // let db = web::Data::new(PkceVerifier{value: "".to_string()});
    HttpServer::new(move|| {
        App::new()
            .app_data(web::Data::new(db.clone()))
            .route("/", web::get().to(healthcheck))
            .route("/Auth", web::get().to(google_auth_url))
            .route("/callback", web::get().to(auth_callback))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}