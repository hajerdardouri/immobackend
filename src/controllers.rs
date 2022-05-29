use std::ffi::OsStr;
use crate::models::{JWTClaim, Listing, User};
use crate::{JWT_SECRET, MONGOCOLLECTIONLISTING, MONGOCOLLECTIONUSERS, MONGO_DB, UPLOADS_DIR};
use actix_multipart::Multipart;
use actix_web::{get, post, web, HttpRequest, HttpResponse, Responder, ResponseError};
use chrono;
use chrono::Duration;
use futures::{StreamExt, TryStreamExt};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use md5;
use mongodb::bson::doc;
use mongodb::bson::oid::ObjectId;
use mongodb::bson::Document;
use mongodb::error::WriteFailure;
use mongodb::options::FindOneOptions;
use mongodb::Client;
use nanoid::nanoid;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::Path;

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
                    password: Some(format!("{:x}", md5::compute(user.password.clone()))),
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
                    sub: db_result.inserted_id.as_object_id().map(|id| id.to_string()).unwrap(),
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
                mongodb::error::ErrorKind::Write(WriteFailure::WriteError(e))
                    if e.code == 11000 =>
                {
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
        if u.password == Some(md5password) {
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
    filter.insert("_id", ObjectId::parse_str(dbg!(claim.claims.sub)).unwrap());
    let mut find_one_options = FindOneOptions::default();
    find_one_options.projection = Some(doc! { "password": 0 });
    let user = users_collection
        .find_one(Some(filter), Some(find_one_options))
        .await
        .unwrap();

    Ok(match user {
        Some(u) => HttpResponse::Ok().json(u),
        None => HttpResponse::NotFound().finish(),
    })
}

//product details

#[derive(Deserialize, Serialize)]
pub struct Product {
    _id: String,
}

#[post("api/product_details")]
pub async fn product_details(
    db: web::Data<Client>,
    p: web::Json<Product>,
) -> actix_web::Result<HttpResponse> {
    let listing_collection = db
        .database(MONGO_DB)
        .collection::<Listing>(MONGOCOLLECTIONLISTING);
    let mut filter = Document::new();
    filter.insert("_id", ObjectId::parse_str(p._id.clone()).unwrap());
    let item = listing_collection
        .find_one(Some(filter), None)
        .await
        .unwrap();

    Ok(match item {
        Some(l) => HttpResponse::Ok().json(l),
        None => HttpResponse::NotFound().body("listing_not_found"),
    })
}

#[derive(Deserialize, Serialize)]
struct UploadResponseFile {
    name: String,
    link: String,
}

#[derive(Deserialize, Serialize)]
struct UploadResponse {
    files: Vec<UploadResponseFile>,
}

#[post("api/upload")]
pub async fn upload(mut payload: Multipart) -> actix_web::Result<HttpResponse> {
    // iterate over multipart stream

    let mut upload_res = UploadResponse { files: vec![] };

    while let Some(mut field) = payload.try_next().await.map_err(|e| e.error_response())? {
        // A multipart/form-data stream has to contain `content_disposition`
        let content_disposition = field
            .content_disposition()
            .ok_or(HttpResponse::BadRequest().body("invalid_file"))?;

        let ext = Path::new(content_disposition.get_filename().ok_or(HttpResponse::BadRequest().body("invalid_file"))?)
            .extension()
            .and_then(OsStr::to_str).map(|e| format!(".{}", e) );
        let filename = format!(
            "{}{}",
            nanoid!(),
            ext.unwrap_or("".to_string())
        );

        let filepath = format!("{}{}", UPLOADS_DIR, filename.clone());

        // File::create is blocking operation, use threadpool
        fs::create_dir_all(UPLOADS_DIR).map_err(|e| e.error_response())?;
        let mut f = web::block(move || std::fs::File::create(filepath))
            .await
            .map_err(|e| e.error_response())?;

        // Field in turn is stream of *Bytes* object
        while let Some(chunk) = field.try_next().await.map_err(|e| e.error_response())? {
            // filesystem operations are blocking, we have to use threadpool
            f = web::block(move || f.write_all(&chunk).map(|_| f))
                .await
                .map_err(|e| e.error_response())?;
        }

        upload_res.files.push(UploadResponseFile {
            name: content_disposition.get_name().unwrap_or("").to_string(),
            link: filename.clone(),
        });
    }

    Ok(HttpResponse::Ok().json(upload_res).into())
}
