use crate::models::{Listing, User};
use crate::{MONGOCOLLECTIONLISTING, MONGOCOLLECTIONUSERS, MONGO_DB};
use actix_web::{get, post, web, HttpResponse, Responder};
use futures::StreamExt;
use mongodb::bson::doc;
use mongodb::bson::oid::ObjectId;
use mongodb::bson::Document;
use mongodb::error::ErrorKind::Write;
use mongodb::error::WriteFailure;
use mongodb::Client;
use serde::{Deserialize, Serialize};

extern crate crypto;
extern crate hyper;
extern crate jwt;
extern crate regex;

//fetch_listing

#[derive(Deserialize)]
pub struct SearchParams {
    q: Option<String>,
}

#[get("api/listing")]
pub async fn listing(db: web::Data<Client>, qs: web::Query<SearchParams>) -> impl Responder {
    let listing_collection = db
        .database(MONGO_DB)
        .collection::<Listing>(MONGOCOLLECTIONLISTING);
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

//Create_listing

#[derive(Deserialize, Serialize)]
pub struct CreateListingData {
    photo: Option<String>,
    title: String,
    location: Option<String>,
    bednum: Option<String>,
    bathnum: Option<String>,
    surfacesize: Option<String>,
    price: Option<String>,
}

#[post("api/create_listing")]
pub async fn create_listing(
    db: web::Data<Client>,
    data: web::Json<CreateListingData>,
) -> impl Responder {
    let listing_collection = db
        .database(MONGO_DB)
        .collection::<Listing>(MONGOCOLLECTIONLISTING);
    return match listing_collection
        .insert_one(
            Listing {
                _id: ObjectId::new(),
                photo: data.photo.clone(),
                title: data.title.clone(),
                location: data.location.clone(),
                bednum: data.bednum.clone(),
                bathnum: data.bathnum.clone(),
                surfacesize: data.surfacesize.clone(),
                price: data.price.clone(),
            },
            None,
        )
        .await
    {
        Ok(db_result) => {
            println!("New document inserted with id {}", db_result.inserted_id);
            HttpResponse::Created().body("insert_successful")
        }
        Err(_) => HttpResponse::InternalServerError().finish(),
    };
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateUserData {
    pub username: String,
    pub email: String,
    pub password: String,
    pub account_type: String,
}

//create_user
#[post("api/create_user")]
pub async fn create_user(db: web::Data<Client>, user: web::Json<CreateUserData>) -> impl Responder {
    let user_collection = db
        .database(MONGO_DB)
        .collection::<User>(MONGOCOLLECTIONUSERS);

    return match user_collection
        .insert_one(
            User {
                _id: ObjectId::new(),
                username: user.username.clone(),
                email: user.email.clone(),
                password: user.password.clone(),
                account_type: user.account_type.clone(),
            },
            // doc! {"username": &users.username, "email": &users.email, "password": &users.password,
            // "account_type": &users.account_type},
            None,
        )
        .await
    {
        Ok(db_result) => {
            println!("New user created with id {}", db_result.inserted_id);
            HttpResponse::Created().body("insert_successful")
        }
        Err(err) => match err.kind.as_ref() {
            Write(WriteFailure::WriteError(e)) if e.code == 11000 => {
                HttpResponse::Unauthorized().body("username_unavailable")
            }
            _ => HttpResponse::InternalServerError().finish(),
        },
    };
}

//Signin

#[derive(Deserialize, Serialize)]
pub struct Signin {
    username: String,
    password: String,
}

#[post("api/signin")]
pub async fn signin(db: web::Data<Client>, user: web::Query<Signin>) -> impl Responder {
    let users_collection = db
        .database(MONGO_DB)
        .collection::<User>(MONGOCOLLECTIONUSERS);
    let mut filter = Document::new();
    filter.insert("username", user.username.clone());
    let db_user = users_collection.find_one(Some(filter), None).await.unwrap();
    if let Some(u) = db_user {
        if u.password == user.password {
            // success
            HttpResponse::Ok().json(u)
        } else {
            // passsword error
            HttpResponse::Unauthorized().body("invalid_password")
        }
    } else {
        // username error
        HttpResponse::Unauthorized().body("invalid_username")
    }
}
