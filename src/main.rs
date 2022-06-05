mod controllers;
mod models;

extern crate actix_web;

use crate::controllers::{create_listing, create_user, delete_wishlist, listing, product_details, show_wishlist, signin, upload, user_profile, wishlist, callback};
use crate::models::User;
use actix_cors::Cors;
use actix_files::Files;
use actix_web::{middleware, web, App, HttpServer};
use mongodb::options::IndexOptions;
use mongodb::{bson::doc, options::ClientOptions, Client, IndexModel};

pub const JWT_SECRET: &'static str = "mytopsecretforjwt";
pub const MONGO_DB: &'static str = "immoexpert";
pub const MONGOCOLLECTIONLISTING: &'static str = "listings";
pub const MONGOCOLLECTIONUSERS: &'static str = "users";
pub const MONGOCOLLECTIONWISHLIST: &'static str = "wishlist";
pub const MONGOCOLLECTIONCALLBACK: &'static str = "callback";

pub const UPLOADS_DIR: &'static str = "./uploads/";

#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));
    std::env::set_var("RUST_LOG", "actix_web=info");

    println!("Connecting to MongoDB..");
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
            .wrap(middleware::Logger::default())
            .wrap(cors)
            .app_data(web::Data::new(client.clone()))
            .service(listing)
            //.route("/todos", web::post().to(controllers::create_listing))
            .service(create_listing)
            .service(create_user)
            .service(signin)
            .service(user_profile)
            .service(product_details)
            .service(upload)
            .service(Files::new("/api/uploads/", UPLOADS_DIR).index_file("index.html"))
            .service(wishlist)
            .service(show_wishlist)
            .service(delete_wishlist)
            .service(callback)
    })
    .bind(("0.0.0.0", 8082))?
    .run()
    .await
}
