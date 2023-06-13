
use actix_web::{web, App, HttpResponse, HttpServer, Responder};
mod oauth;
use oauth::{google_auth, callback_handler};
async fn healthcheck() -> impl Responder {
    HttpResponse::Ok().body("health check success")
}


#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .route("/", web::get().to(healthcheck))
            .route("/Auth", web::get().to(google_auth))
            .route("/callback", web::get().to(callback_handler))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}