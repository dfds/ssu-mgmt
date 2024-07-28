use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Envelope {
    #[serde(rename = "type")]
    pub _type : String,
    pub message_id : String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvelopeWithPayload<T> {
    #[serde(rename = "type")]
    pub _type : String,
    pub message_id : String,
    pub data: T
}

pub struct Context {
    pub event : Envelope,
    pub msg : String,
    pub context : crate::misc::context::Context
}