use rdkafka::error::KafkaError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Catch-all error type")]
    Any(Box<dyn std::error::Error + Send>),
    #[error("Request error")]
    RequestError(Box<dyn std::error::Error + Send>),
    #[error("serde_json error")]
    SerdeJsonError(#[from] serde_json::Error),
    #[error("serde_yaml error: {0}")]
    SerdeYamlError(#[from] serde_yaml::Error),
    #[error("config error")]
    ConfigError(Box<dyn std::error::Error + Send>),
    #[error("io error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("io error: {0}")]
    KafkaError(#[from] KafkaError),
    #[error("Database error")]
    DbError(Box<dyn std::error::Error + Send>),
}

pub type SsuResult<T> = Result<T, Error>;

impl From<reqwest::Error> for Error {
    fn from(value: reqwest::Error) -> Self {
        Self::RequestError(Box::new(value))
    }
}


impl From<config::ConfigError> for Error {
    fn from(value: config::ConfigError) -> Self {
        Self::ConfigError(Box::new(value))
    }
}
