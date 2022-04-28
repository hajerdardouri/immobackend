mod controllers;
mod models;

extern crate actix_web;

use crate::controllers::listing;
use actix_cors::Cors;
use actix_web::{web, App, HttpServer};
use mongodb::{options::ClientOptions, Client};

#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    std::env::set_var("RUST_LOG", "actix_web=debug");
    let mut client_options = ClientOptions::parse("mongodb://127.0.0.1:27017/test")
        .await
        .unwrap();
    client_options.app_name = Some("Todolist".to_string());
    let client = web::Data::new(Client::with_options(client_options).unwrap());

    HttpServer::new(move || {
        let cors = Cors::allow_any_origin(Default::default())
            .allow_any_header()
            .allow_any_method();
        App::new()
            .wrap(cors)
            .app_data(client.clone())
            .service(listing)
    })
    .bind(("0.0.0.0", 8082))?
    .run()
    .await
}
