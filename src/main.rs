mod controllers;
mod models;

extern crate actix_web;

use crate::controllers::{create_listing, create_user, listing, signin};
use crate::models::User;
use actix_cors::Cors;
use actix_web::{web, App, HttpServer};
use mongodb::options::IndexOptions;
use mongodb::{bson::doc, options::ClientOptions, Client, IndexModel};

pub const MONGO_DB: &'static str = "immoexpert";
pub const MONGOCOLLECTIONLISTING: &'static str = "listings";
pub const MONGOCOLLECTIONUSERS: &'static str = "users";

#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    std::env::set_var("RUST_LOG", "actix_web=debug");
    let mut client_options = ClientOptions::parse("mongodb://127.0.0.1:27017/listings")
        .await
        .unwrap();
    client_options.app_name = Some("Todolist".to_string());
    let client = Client::with_options(client_options).unwrap();

    let mut index_options = IndexOptions::default();
    index_options.unique = Some(true);
    let mut index_model = IndexModel::default();
    index_model.keys = doc! { "username": 1 };
    index_model.options = Some(index_options);
    let _ = client
        .database(MONGO_DB)
        .collection::<User>(MONGOCOLLECTIONUSERS)
        .create_index(index_model, None)
        .await;

    HttpServer::new(move || {
        let cors = Cors::allow_any_origin(Default::default())
            .allow_any_header()
            .allow_any_method();
        App::new()
            .wrap(cors)
            .app_data(web::Data::new(client.clone()))
            .service(listing)
            //.route("/todos", web::post().to(controllers::create_listing))
            .service(create_listing)
            .service(create_user)
            .service(signin)
    })
    .bind(("0.0.0.0", 8082))?
    .run()
    .await
}
