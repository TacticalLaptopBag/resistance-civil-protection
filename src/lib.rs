pub mod email;

use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::response::Response;
use lettre::{Message, SmtpTransport, Transport};
use log::{debug, error};
use serde::{Deserialize, Serialize};
use std::fs::Permissions;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::{env, fs};

const CONFIG_PATH: &str = "/etc/resistance/civil-protection.conf";

const EMAIL_ADDRESS_REGEX: &str = r"\S+@\S+\.\S\S+";
const EMAIL_IDENTITY_REGEX: &str = r"^.+ <\S+@\S+\.\S\S+>$";
const EMAIL_IDENTITY_NAME_REGEX: &str = r"^.+ ";
const EMAIL_IDENTITY_ADDRESS_REGEX: &str = r" <\S+@\S+\.\S\S+>$";

fn get_config_path() -> String {
    if env::var("RESISTANCE_DEBUG").is_ok() {
        return "./resistance-conf/civil-protection.conf".into();
    }

    return CONFIG_PATH.into();
}

#[derive(Serialize, Deserialize, Debug)]
struct Config {
    email: email::Identity,
    // TODO: Keeping a password in RAM like this isn't a good idea.
    // Definitely need a separate file for it, which is only read from when logging in.
    // This file should have mode 0o600
    password: String,
    email_setting: email::Settings,
    squadmates: Vec<email::Identity>,
}

pub struct CivilProtection {
    config: Option<Config>,
    mailer: Option<SmtpTransport>,
}

impl CivilProtection {
    pub fn new() -> CivilProtection {
        return CivilProtection {
            config: load_config(),
            mailer: None,
        };
    }

    pub fn login(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let conf = self.check_config()?;
        let credentials = Credentials::new(
            conf.email.email.to_owned(),
            conf.password.to_owned(),
        );

        let mail_builder = match conf.email_setting.encryption {
            email::Encryption::TLS => SmtpTransport::relay(conf.email_setting.server.as_str()),
            email::Encryption::STARTTLS => {
                SmtpTransport::starttls_relay(conf.email_setting.server.as_str())
            }
        };
        let mailer = mail_builder?.credentials(credentials).build();
        self.mailer = Some(mailer);

        return Ok(());
    }

    pub fn add_squadmate(&mut self, squadmate: email::Identity) -> Result<(), &str> {
        let conf = self.check_config_mut()?;
        conf.squadmates.push(squadmate);
        return Ok(());
    }

    pub fn notify_squadmates(&self) -> Result<(), Box<dyn std::error::Error>> {
        let conf = self.check_config()?;
        
        let message = email::Message {
            from: conf.email.clone(),
            subject: "[Resistance] Test Email".into(),
            body: "This is a test of Resistance Civil Protection".into(),
        };

        for squadmate in &conf.squadmates {
            self.send_email(&message, &squadmate)?;
        }

        return Ok(());
    }

    pub fn create_config(&mut self, identity: email::Identity, password: String) -> Result<(), Box<dyn std::error::Error>> {
        if self.config.is_some() {
            return Err("Config exists".into());
        }

        let settings = get_server_settings_from_address(identity.email.as_str())?;
        self.config = Some(Config {
            email: identity,
            password,
            email_setting: settings,
            squadmates: vec![],
        });

        return Ok(());
    }

    fn send_email(
        &self,
        message: &email::Message,
        recipient: &email::Identity,
    ) -> Result<Response, Box<dyn std::error::Error>> {
        let mailer = self.check_mailer()?;

        debug!("Sending email");
        let email = Message::builder()
            .from(
                format!("{} <{}>", message.from.name, message.from.email)
                    .parse()
                    .unwrap(),
            )
            .to(format!("{} <{}>", recipient.name, recipient.email)
                .parse()
                .unwrap())
            .subject(message.subject.as_str())
            // This could be TEXT_HTML
            .header(ContentType::TEXT_PLAIN)
            .body(message.body.clone())
            .unwrap();

        return Ok(mailer.send(&email)?);
    }

    fn check_mailer(&self) -> Result<&SmtpTransport, &str> {
        return match &self.mailer {
            Some(mailer) => Ok(mailer),
            None => Err("Not logged in"),
        };
    }

    fn check_config(&self) -> Result<&Config, &str> {
        return match &self.config {
            Some(conf) => Ok(conf),
            None => Err("Missing config"),
        };
    }

    fn check_config_mut(&mut self) -> Result<&mut Config, &str> {
        return match &mut self.config {
            Some(conf) => Ok(conf),
            None => Err("Missing config"),
        };
    }

    pub fn save_config(&self) -> Result<(), Box<dyn std::error::Error>> {
        let config_path_str = get_config_path();
        let config_path = Path::new(config_path_str.as_str());
        match config_path.parent() {
            Some(parent) => {
                fs::create_dir_all(parent)?;
                fs::set_permissions(parent, Permissions::from_mode(0o700))?;
            }
            None => panic!("Config path is either blank, or parent directory is root!"),
        }

        // let config_data = bson::to_bson(&self.config)?;
        // let config_bytes = bson::ser::to_vec(&config_data)?;
        let config_data = serde_json::to_string_pretty(&self.config)?;
        let config_bytes = config_data.into_bytes();
        fs::write(config_path, config_bytes)?;
        fs::set_permissions(config_path, Permissions::from_mode(0o600))?;

        return Ok(());
    }
}

fn load_config() -> Option<Config> {
    let config_path_str = get_config_path();
    let config_path = Path::new(config_path_str.as_str());
    let config_bytes = match fs::read(config_path) {
        Ok(bytes) => bytes,
        Err(e) => {
            error!("Error reading config file: {}", e);
            return None;
        }
    };

    return match serde_json::from_slice(&config_bytes) {
        Ok(config) => Some(config),
        Err(e) => {
            error!("Error while deserializing config data: {}", e);
            return None;
        }
    };

    // return match bson::from_slice(&config_bytes.unwrap()) {
    //     Ok(config) => Some(config),
    //     Err(e) => {
    //         // Error while deserializing config file
    //         // TODO: This should throw flags to Overwatch and load a backed up copy of the config,
    //         // if possible. For now, creating a new config is fine for testing
    //         error!("Error while deserializing config data: {e:?}");
    //         // return create_config();
    //         return None;
    //     }
    // };
}

fn get_server_settings_from_address(email_address: &str) -> Result<email::Settings, &str> {
    return match email_address.split_once("@") {
        Some((_account, domain)) => {
            let server: String;
            let encryption: email::Encryption;
            match domain {
                "gmail.com" => {
                    server = "smtp.gmail.com".to_owned();
                    encryption = email::Encryption::TLS;
                }
                "hotmail.com" | "outlook.com" | "msn.com" => {
                    server = "outlook.office365.com".to_owned();
                    encryption = email::Encryption::STARTTLS;
                }
                "yahoo.com" => {
                    server = "smtp.mail.yahoo.com".to_owned();
                    encryption = email::Encryption::TLS;
                }
                "icloud.com" => {
                    server = "smtp.mail.me.com".to_owned();
                    encryption = email::Encryption::TLS;
                }
                "aol.com" | "verizon.net" => {
                    server = "smtp.aol.com".to_owned();
                    encryption = email::Encryption::STARTTLS;
                }
                "comcast.net" => {
                    server = "smtp.comcast.net".to_owned();
                    encryption = email::Encryption::TLS;
                }
                _ => return Err("Unknown settings for given domain")
            }

            Ok(email::Settings { server, encryption })
        },
        None => {
            error!("Email address {} is invalid!", email_address);

            Err("Invalid email address")
        },
    };
}
