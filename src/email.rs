use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Identity {
    pub name: String,
    pub email: String,
}

#[derive(Clone)]
pub struct Message {
    pub from: Identity,
    pub subject: String,
    pub body: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum Encryption {
    TLS,
    STARTTLS,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Settings {
    pub server: String,
    pub encryption: Encryption,
}

