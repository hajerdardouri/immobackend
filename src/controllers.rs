use crate::models::Test;
use actix_web::{get, web, HttpResponse, Responder};
use futures::StreamExt;
use mongodb::bson::doc;
use mongodb::bson::Document;
use mongodb::Client;
use serde::{Deserialize, Serialize};

extern crate regex;
#[derive(Deserialize, Serialize)]
pub struct Todo {
    pub content: String,
    pub is_done: bool,
}
#[derive(Serialize)]
struct Response {
    message: String,
}

const MONGO_DB: &'static str = "test";
const MONGOCOLLECTION: &'static str = "test";

#[get("api/listing")]
pub async fn listing(data: web::Data<Client>, qs: web::Query<SearchParams>) -> impl Responder {
    let listing_collection = data.database(MONGO_DB).collection::<Test>(MONGOCOLLECTION);

    let mut filter = Document::new();

    qs.q.as_ref().map(|q| {
        filter.insert(
            "title",
            doc! { "$regex": format!("{}", q), "$options": "i" },
        )
    });

    let mut cursor = listing_collection.find(Some(filter), None).await.unwrap();
    let mut results = Vec::new();
    while let Some(result) = cursor.next().await {
        match result {
            Ok(document) => {
                results.push(document);
            }
            _ => {
                return HttpResponse::InternalServerError().finish();
            }
        }
    }
    HttpResponse::Ok().json(results)
}

#[derive(Deserialize)]
struct SearchParams {
    q: Option<String>,
}
