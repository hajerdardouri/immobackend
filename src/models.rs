use mongodb::bson::oid::ObjectId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Test {
    pub _id: ObjectId,
    pub photo: Option<String>,
    pub title: String,
    pub location: Option<String>,
    pub bednum: Option<String>,
    pub bathnum: Option<String>,
    pub surfacesize: Option<String>,
    pub price: Option<String>,
}
