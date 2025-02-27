use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Identity {
    pub name: String,
    pub email: String,
}

impl Identity {
    pub fn eq(&self, other: &Identity) -> bool {
        return self.name == other.name && self.email == other.email;
    }
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
pub enum Settings {
    SMTP(SMTPSettings),
    SENDMAIL(SendMailSettings),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SMTPSettings {
    pub server: String,
    pub encryption: Encryption,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SendMailSettings {

}

