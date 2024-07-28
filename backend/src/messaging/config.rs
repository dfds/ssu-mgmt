use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct MessagingConfig {
    pub credentials : KafkaCredentials,
    pub bootstrap_servers : String,
    pub group_id : String,
    pub sasl_mechanism : String,
    pub security_protocol : String
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct KafkaCredentials {
    pub username : String,
    pub password : String,
}