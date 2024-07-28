use log::info;
use serde::{Deserialize, Serialize};
use crate::messaging::model::{Context, EnvelopeWithPayload};
use crate::misc::error::SsuResult;
use crate::service::bg::Message;

pub fn user_action_handler(context: Context) -> SsuResult<()> {
    let ewp : EnvelopeWithPayload<UserActionMessage> = serde_json::from_str(&context.msg)?;
    context.context.bg_sender.send(Message::UserAction(ewp));
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserActionMessage {
    pub action: String,
    pub method: String,
    pub path: String,
    #[serde(rename = "requestData")]
    pub request_data: serde_json::Value,
    pub service: String,
    pub timestamp: i64,
    pub username: String,
}