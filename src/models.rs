use mongodb::bson::oid::ObjectId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Listing {
    pub _id: ObjectId,
    pub user_id: ObjectId,
    pub photo: Option<String>,
    pub title: String,
    pub location: Option<String>,
    pub bednum: Option<i32>,
    pub bathnum: Option<i32>,
    pub surfacesize: Option<i32>,
    pub price: Option<i32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct User {
    pub _id: ObjectId,
    pub username: String,
    pub email: String,
    pub password: Option<String>,
    pub account_type: String,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct Wishlist {
    pub listing_id: ObjectId,
    pub user_id: ObjectId,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct Callback {
    pub _id: ObjectId,
    pub user_id: ObjectId,
    pub number: i32,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct JWTClaim {
    pub aud: String,
    pub exp: usize,
    pub iat: usize,
    pub iss: String,
    pub nbf: usize,
    pub sub: String,
}
