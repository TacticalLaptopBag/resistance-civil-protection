use std::env;
use std::fs;
use std::fs::Permissions;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use log::error;
use serde::{Deserialize, Serialize};

use crate::email;
use crate::cons;
use crate::email::SendMailSettings;

fn get_config_path() -> String {
    if env::var("RESISTANCE_DEBUG").is_ok() {
        return "./resistance-conf/civil-protection.conf".into();
    }

    return cons::CONFIG_PATH.into();
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    pub email: email::Identity,
    pub email_setting: email::Settings,
    pub squadmates: Vec<email::Identity>,
}

impl Config {
    pub fn exists() -> std::io::Result<bool> {
        match fs::exists(get_config_path()) {
            Ok(result) => Ok(result),
            Err(e) => Err(e),
        }
    }

    pub fn save(&self) -> Result<(), Box<dyn std::error::Error>> {
        let config_path_str = get_config_path();
        let config_path = Path::new(config_path_str.as_str());
        match config_path.parent() {
            Some(parent) => {
                fs::create_dir_all(parent)?;
                fs::set_permissions(parent, Permissions::from_mode(0o700))?;
            }
            None => panic!("Config path is either blank, or parent directory is root!"),
        }

        let config_data = bson::to_bson(self)?;
        let config_bytes = bson::ser::to_vec(&config_data)?;
        // let config_data = serde_json::to_string_pretty(&self.config)?;
        // let config_bytes = config_data.into_bytes();
        fs::write(config_path, config_bytes)?;
        fs::set_permissions(config_path, Permissions::from_mode(0o600))?;

        return Ok(());
    }

    pub fn load() -> Result<Config, Box<dyn std::error::Error>> {
        let config_path_str = get_config_path();
        let config_path = Path::new(config_path_str.as_str());
        let config_bytes = match fs::read(config_path) {
            Ok(bytes) => bytes,
            Err(e) => return Err(format!("Error reading config file: {}", e).into()),
        };

        // return match serde_json::from_slice(&config_bytes) {
        //     Ok(config) => Some(config),
        //     Err(e) => {
        //         error!("Error while deserializing config data: {}", e);
        //         return None;
        //     }
        // };

        return match bson::from_slice(&config_bytes) {
            Ok(config) => Ok(config),
            Err(e) => {
                // Error while deserializing config file
                // TODO: This should throw flags to Overwatch and load a backed up copy of the config,
                // if possible. For now, creating a new config is fine for testing
                Err(format!("Error while deserializing config data: {e:?}").into())
                // return create_config();
            }
        };
    }

    pub fn delete() -> Result<(), Box<dyn std::error::Error>> {
        let config_path = get_config_path();
        if fs::exists(&config_path)? {
            return Err("Config already deleted".into());
        }

        fs::remove_file(&config_path)?;
        return Ok(());
    }

    pub fn new_smtp(identity: email::Identity, password: String) -> Result<Config, Box<dyn std::error::Error>> {
        let config_path = get_config_path();
        if fs::exists(&config_path)? {
            return Err("Config already deleted".into());
        }

        let mut settings = get_server_settings_from_address(identity.email.as_str())?;
        settings.set_password(&password);
        let config = Config {
            email: identity,
            email_setting: email::Settings::SMTP(settings),
            squadmates: vec![],
        };

        config.save()?;
        Ok(config)
    }

    pub fn new_sendmail(identity: email::Identity) -> Result<Config, Box<dyn std::error::Error>> {
        let config_path = get_config_path();
        if fs::exists(&config_path)? {
            return Err("Config already deleted".into());
        }

        let settings = SendMailSettings {};
        let config = Config {
            email: identity,
            email_setting: email::Settings::SENDMAIL(settings),
            squadmates: vec![],
        };

        config.save()?;
        Ok(config)
    }
}

fn get_server_settings_from_address(email_address: &str) -> Result<email::SMTPSettings, &str> {
    return match email_address.split_once("@") {
        Some((_account, domain)) => {
            let server: String;
            let encryption: email::Encryption;
            match domain.trim().to_lowercase().as_str() {
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
                _ => {
                    error!("Unrecognized domain: {}", domain);
                    return Err("Unknown settings for given domain")
                }
            }

            Ok(email::SMTPSettings::new(server, encryption))
        },
        None => {
            error!("Email address {} is invalid!", email_address);

            Err("Invalid email address")
        },
    };
}
