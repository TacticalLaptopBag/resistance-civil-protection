use std::fmt::Display;

use aes_gcm::{Aes256Gcm, KeyInit};
use lettre::message::header::ContentType;
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

impl Display for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} <{}>", self.name, self.email)
    }
}

#[derive(Clone)]
pub struct Message {
    pub from: Identity,
    pub subject: String,
    pub body: String,
}

impl Message {
    pub fn to_lettre(&self, recipients: &[Identity]) -> lettre::Message {
        let mut builder = lettre::Message::builder()
            .from(
                format!("{}", self.from)
                    .parse()
                    .unwrap(),
            )
            .subject(self.subject.as_str())
            // This could be TEXT_HTML
            .header(ContentType::TEXT_PLAIN);
        for recipient in recipients {
            builder = builder.to(
                format!("{}", recipient).parse().unwrap()
            );
        }

        builder.body(self.body.clone()).unwrap()
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub enum Encryption {
    TLS,
    STARTTLS,
}

impl Display for Encryption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Encryption::TLS => write!(f, "TLS")?,
            Encryption::STARTTLS => write!(f, "StartTLS")?,
        };
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub enum Settings {
    SMTP(SMTPSettings),
    SENDMAIL(SendMailSettings),
}

impl Display for Settings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Settings::SMTP(settings) => write!(f, "SMTP | {} | {}", settings.server, settings.encryption)?,
            Settings::SENDMAIL(_settings) => write!(f, "sendmail")?,
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SMTPSettings {
    pub server: String,
    pub encryption: Encryption,
    password: String,
}

impl SMTPSettings {
    pub fn new(server: String, encryption: Encryption) -> SMTPSettings {
        SMTPSettings {
            server, 
            encryption,
            password: String::new(),
        }
    }

    // TODO: Encrypt and decrypt password
    pub fn set_password(&mut self, password: &String) {
        self.password = password.clone();
    }

    pub fn password(&self) -> &String {
        &self.password
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SendMailSettings {

}

