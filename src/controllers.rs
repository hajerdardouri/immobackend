use crate::models::{JWTClaim, Listing, User};
use crate::{JWT_SECRET, MONGOCOLLECTIONLISTING, MONGOCOLLECTIONUSERS, MONGO_DB};
use actix_web::{get, post, web, HttpRequest, HttpResponse, Responder};
use chrono;
use chrono::Duration;
use futures::StreamExt;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use md5;
use mongodb::bson::doc;
use mongodb::bson::oid::ObjectId;
use mongodb::bson::Document;
use mongodb::error::ErrorKind::Write;
use mongodb::error::WriteFailure;
use mongodb::options::FindOneOptions;
use mongodb::Client;
use serde::{Deserialize, Serialize};

//fetch_listing
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    company: String,
    exp: usize,
}

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
        );
        filter.insert("location", q);
        filter.insert("bednum", q);
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
    bednum: Option<i32>,
    bathnum: Option<i32>,
    surfacesize: Option<i32>,
    price: Option<i32>,
}

#[post("api/create_listing")]
pub async fn create_listing(
    db: web::Data<Client>,
    data: web::Json<CreateListingData>,
    request: HttpRequest,
) -> actix_web::Result<HttpResponse> {
    let listing_collection = db
        .database(MONGO_DB)
        .collection::<Listing>(MONGOCOLLECTIONLISTING);

    let req_headers = request.headers();
    let basic_auth_header = req_headers.get("Authorization");
    let basic_auth = basic_auth_header
        .ok_or(HttpResponse::Unauthorized().body("missing_authorization_header"))?
        .to_str()
        .map_err(|_| HttpResponse::Unauthorized().body("invalid_authorization_header"))?
        .replace("Bearer ", "");

    let claim = decode::<JWTClaim>(
        &basic_auth,
        &DecodingKey::from_secret(JWT_SECRET.as_ref()),
        &{
            let mut validation = Validation::default();
            validation.validate_exp = true;
            validation
        },
    )
    .map_err(|e| HttpResponse::Unauthorized().body(e.to_string()))?;

    return Ok(
        match listing_collection
            .insert_one(
                Listing {
                    _id: ObjectId::new(),
                    user_id: ObjectId::parse_str(claim.claims.sub.as_str()).map_err(|_| {
                        HttpResponse::InternalServerError().body("could_not_parse_userId")
                    })?,
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
        },
    );
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateUserData {
    pub username: String,
    pub email: String,
    pub password: String,
    pub account_type: String,
}
#[derive(Deserialize, Serialize)]
pub struct SignupPayload {
    token: String,
}
//create_user
#[post("api/create_user")]
pub async fn create_user(
    db: web::Data<Client>,
    user: web::Json<CreateUserData>,
) -> actix_web::Result<HttpResponse> {
    let user_collection = db
        .database(MONGO_DB)
        .collection::<User>(MONGOCOLLECTIONUSERS);

    Ok(
        match user_collection
            .insert_one(
                User {
                    _id: ObjectId::new(),
                    username: user.username.clone(),
                    email: user.email.clone(),
                    password: format!("{:x}", md5::compute(user.password.clone())),
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

                let jwt_claim = JWTClaim {
                    aud: "public".to_string(),
                    exp: (chrono::Utc::now() + Duration::seconds(2000)).timestamp() as usize,
                    iat: chrono::Utc::now().timestamp() as usize,
                    iss: "Tayara".to_string(),
                    nbf: chrono::Utc::now().timestamp() as usize,
                    sub: db_result.inserted_id.to_string(),
                };
                let token = encode(
                    &Header::default(),
                    &jwt_claim,
                    &EncodingKey::from_secret(JWT_SECRET.as_ref()),
                )
                .map_err(|_| {
                    HttpResponse::InternalServerError().body("could_not_encode_jwt_token")
                })?;
                HttpResponse::Created().json(SigninPayload { token })
            }
            Err(err) => match err.kind.as_ref() {
                Write(WriteFailure::WriteError(e)) if e.code == 11000 => {
                    HttpResponse::Unauthorized().body("username_unavailable")
                }
                _ => HttpResponse::InternalServerError().finish(),
            },
        },
    )
}

//Signin

#[derive(Deserialize, Serialize)]
pub struct SigninData {
    username: String,
    password: String,
}
#[derive(Deserialize, Serialize)]
pub struct SigninPayload {
    token: String,
}
#[post("api/signin")]
pub async fn signin(
    db: web::Data<Client>,
    user: web::Json<SigninData>,
) -> actix_web::Result<HttpResponse> {
    let users_collection = db
        .database(MONGO_DB)
        .collection::<User>(MONGOCOLLECTIONUSERS);
    let mut filter = Document::new();
    filter.insert("username", user.username.clone());
    let db_user = users_collection.find_one(Some(filter), None).await.unwrap();

    let md5password = format!("{:x}", md5::compute(user.password.clone()));

    if let Some(u) = db_user {
        if u.password == md5password {
            // success
            let jwt_claim = JWTClaim {
                aud: "public".to_string(),
                exp: (chrono::Utc::now() + Duration::seconds(2000)).timestamp() as usize,
                iat: chrono::Utc::now().timestamp() as usize,
                iss: "Tayara".to_string(),
                nbf: chrono::Utc::now().timestamp() as usize,
                sub: u._id.to_string(),
            };
            let token = encode(
                &Header::default(),
                &jwt_claim,
                &EncodingKey::from_secret(JWT_SECRET.as_ref()),
            )
            .map_err(|_| HttpResponse::InternalServerError().body("could_not_encode_jwt_token"))?;

            Ok(HttpResponse::Ok().json(SigninPayload { token }))
        } else {
            // passsword error
            Ok(HttpResponse::Unauthorized().body("invalid_password"))
        }
    } else {
        // username error
        Ok(HttpResponse::Unauthorized().body("invalid_username"))
    }
}

#[post("api/user_profile")]
pub async fn user_profile(
    db: web::Data<Client>,
    request: HttpRequest,
) -> actix_web::Result<HttpResponse> {
    let users_collection = db
        .database(MONGO_DB)
        .collection::<User>(MONGOCOLLECTIONUSERS);
    let req_headers = request.headers();
    let basic_auth_header = req_headers.get("Authorization");
    let basic_auth = basic_auth_header
        .ok_or(HttpResponse::Unauthorized().body("missing_authorization_header"))?
        .to_str()
        .map_err(|_| HttpResponse::Unauthorized().body("invalid_authorization_header"))?
        .replace("Bearer ", "");

    let claim = decode::<JWTClaim>(
        &basic_auth,
        &DecodingKey::from_secret(JWT_SECRET.as_ref()),
        &{
            let mut validation = Validation::default();
            validation.validate_exp = true;
            validation
        },
    )
    .map_err(|e| HttpResponse::Unauthorized().body(e.to_string()))?;

    let mut filter = Document::new();
    filter.insert("_id", ObjectId::parse_str(claim.claims.sub).unwrap());
    let mut find_one_options = FindOneOptions::default();
    find_one_options.projection = doc! {"password":0};
    let user = users_collection
        .find_one(Some(filter), Some(find_one_options))
        .await
        .unwrap();
    Ok(match user(HttpResponse::Ok().json(user)).await {
        Err(_) => HttpResponse::NotFound().finish(),
    })
}
