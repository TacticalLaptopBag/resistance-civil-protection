use std::{env, fmt::Display, fs, os::unix::fs::PermissionsExt};

use aes_gcm::{aead::OsRng, Aes256Gcm, KeyInit};
use lettre::message::header::ContentType;
use serde::{Deserialize, Serialize};

use crate::{cons, crypt::{self, decrypt}};

fn get_pass_path() -> String {
    if env::var("RESISTANCE_DEBUG").is_ok() {
        return "./resistance-conf/civil-protection.secret".into();
    }

    return cons::PASS_PATH.into();
}

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

    pub fn set_password(&mut self, password: &String) -> Result<(), Box<dyn std::error::Error>> {
        let pass_path = get_pass_path();
        let key = match fs::read(&pass_path) {
            Ok(key) => key,
            Err(_) => {
                let new_key = Aes256Gcm::generate_key(OsRng);
                fs::write(&pass_path, new_key)?;
                let perms = fs::Permissions::from_mode(0o600);
                fs::set_permissions(&pass_path, perms)?;
                new_key.to_vec()
            },
        };

        let encrypted_pass = crypt::encrypt(&key, password.as_bytes());
        self.password = encrypted_pass;
        Ok(())
    }

    pub fn password(&self) -> Result<String, Box<dyn std::error::Error>> {
        let key = match fs::read(get_pass_path()) {
            Ok(key) => key,
            Err(_) => return Err("failed to load password".into()),
        };
        let decrypted_pass = decrypt(&key, &self.password);
        let decrypted_pass_str = String::from_utf8(decrypted_pass)?;
        Ok(decrypted_pass_str)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SendMailSettings {

}

