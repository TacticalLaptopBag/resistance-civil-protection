pub mod email;

use email::{SMTPSettings, SendMailSettings};
use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::response::Response;
use lettre::{Message, SmtpTransport, Transport};
use log::{debug, error};
use regex::Regex;
use serde::{Deserialize, Serialize};
use tempfile::tempfile;
use std::fs::Permissions;
use std::io::{Seek, SeekFrom, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::{env, fs, io};
use base64::prelude::*;

const CONFIG_PATH: &str = "/etc/resistance/civil-protection.conf";
const PASS_PATH: &str = "/etc/resistance/civil-protection.secret";

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

fn get_pass_path() -> String {
    if env::var("RESISTANCE_DEBUG").is_ok() {
        return "./resistance-conf/civil-protection.secret".into();
    }

    return PASS_PATH.into();
}

#[derive(Serialize, Deserialize, Debug)]
struct Config {
    email: email::Identity,
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

    pub fn is_config_loaded(&self) -> bool {
        return self.config.is_some();
    }

    pub fn is_logged_in(&self) -> bool {
        return self.mailer.is_some();
    }

    pub fn login(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let conf = self.check_config()?;
        
        return match &conf.email_setting {
            email::Settings::SMTP(smtp_settings) => {
                let mailer = self.login_smtp(smtp_settings, &conf.email.email)?;
                self.mailer = Some(mailer);
                Ok(())
            },
            email::Settings::SENDMAIL(send_mail_settings) => {
                self.login_sendmail(send_mail_settings)?;
                Ok(())
            },
        }
    }

    fn login_smtp(&self, smtp_settings: &SMTPSettings, email: &String) -> Result<SmtpTransport, Box<dyn std::error::Error>> {
        // TODO: Need to decrypt password
        let password_encoded = fs::read_to_string(get_pass_path())?;
        let password_bytes = BASE64_STANDARD_NO_PAD.decode(password_encoded)?;
        let password = String::from_utf8(password_bytes)?;

        let credentials = Credentials::new(
            email.to_owned(),
            password.to_owned(),
        );

        let mail_builder = match smtp_settings.encryption {
            email::Encryption::TLS => SmtpTransport::relay(smtp_settings.server.as_str()),
            email::Encryption::STARTTLS => {
                SmtpTransport::starttls_relay(smtp_settings.server.as_str())
            }
        };
        let mailer = mail_builder?.credentials(credentials).build();
        mailer.test_connection()?;

        return Ok(mailer);
    }

    fn login_sendmail(&self, _send_mail_settings: &SendMailSettings) -> Result<(), std::io::Error> {
        let status = Command::new("which")
            .arg("sendmail")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .status()?;
        if !status.success() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "sendmail not found",
            ));
        }

        Ok(())
    }

    pub fn add_squadmate(&mut self, squadmate: email::Identity) -> Result<(), &str> {
        let conf = self.check_config_mut()?;
        let email_regex = Regex::new(EMAIL_ADDRESS_REGEX).unwrap();
        if !email_regex.is_match(&squadmate.email) {
            return Err("Invalid email format")
        }
        conf.squadmates.push(squadmate);
        return Ok(());
    }

    pub fn rm_squadmate(&mut self, squadmate: &email::Identity) -> Result<bool, &str> {
        let conf = self.check_config_mut()?;
        let mut idx = 0;
        for squadmate_it in &conf.squadmates {
            if *squadmate_it == *squadmate {
                break;
            }
            idx += 1;
        }

        if idx >= conf.squadmates.len() {
            return Ok(false);
        }

        conf.squadmates.remove(idx);
        return Ok(true);
    }

    pub fn find_squadmate_by_email(&mut self, email: &str) -> Result<Option<&email::Identity>, &str> {
        let conf = self.check_config_mut()?;
        let mut idx = 0;
        for squadmate in &conf.squadmates {
            if squadmate.email == email {
                break;
            }
            idx += 1;
        }

        if idx >= conf.squadmates.len() {
            return Ok(None);
        }

        return Ok(Some(&conf.squadmates[idx]));
    }

    pub fn find_squadmate_by_name(&mut self, name: &str) -> Result<Option<&email::Identity>, &str> {
        let conf = self.check_config_mut()?;
        let mut idx = 0;
        for squadmate in &conf.squadmates {
            if squadmate.name == name {
                break;
            }
            idx += 1;
        }

        if idx >= conf.squadmates.len() {
            return Ok(None);
        }

        return Ok(Some(&conf.squadmates[idx]));
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

    pub fn delete_config(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if self.config.is_none() {
            return Err("Config already deleted".into());
        }

        self.config = None;

        let pass_path = get_pass_path();
        if fs::exists(&pass_path)? {
            fs::remove_file(pass_path)?;
        }
        fs::remove_file(get_config_path())?;
        return Ok(());
    }

    pub fn create_config_smtp(&mut self, identity: email::Identity, password: String) -> Result<(), Box<dyn std::error::Error>> {
        if self.config.is_some() {
            return Err("Config exists".into());
        }

        let settings = get_server_settings_from_address(identity.email.as_str())?;
        self.config = Some(Config {
            email: identity,
            email_setting: email::Settings::SMTP(settings),
            squadmates: vec![],
        });

        // TODO: Need to encrypt password
        let password_encoded = BASE64_STANDARD_NO_PAD.encode(password);
        let path_str = get_pass_path();
        let path = Path::new(&path_str);
        match path.parent() {
            Some(parent) => fs::create_dir_all(parent)?,
            None => (),
        };
        fs::write(path, password_encoded)?;
        fs::set_permissions(path, Permissions::from_mode(0o600))?;

        return Ok(());
    }

    pub fn create_config_sendmail(&mut self, identity: email::Identity) -> Result<(), Box<dyn std::error::Error>> {
        if self.config.is_some() {
            return Err("config exists".into());
        }

        let settings = SendMailSettings {};
        self.config = Some(Config {
            email: identity,
            email_setting: email::Settings::SENDMAIL(settings),
            squadmates: vec![],
        });

        Ok(())
    }

    fn send_email(
        &self,
        message: &email::Message,
        recipient: &email::Identity,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let conf = self.check_config()?;
        return match &conf.email_setting {
            email::Settings::SMTP(_) => {
                self.send_email_smtp(message, recipient)
            },
            email::Settings::SENDMAIL(_) => {
                self.send_email_sendmail(message, recipient)
            },
        };
    }

    fn send_email_smtp(
        &self,
        message: &email::Message,
        recipient: &email::Identity,
    ) -> Result<(), Box<dyn std::error::Error>> {
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

        mailer.send(&email)?;
        Ok(())
    }

    fn send_email_sendmail(
        &self,
        message: &email::Message,
        recipient: &email::Identity,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let subject_line = "subject:".to_owned() + &message.subject + "\n";
        let from_line = "from:".to_owned() + &message.from.email + "\n";

        let content = subject_line + from_line.as_str() + "\n" + message.body.as_str();
        let mut sendmail_file = tempfile()?;
        sendmail_file.write_all(content.as_bytes())?;
        sendmail_file.flush()?;
        sendmail_file.seek(SeekFrom::Start(0))?;

        let status = Command::new("sendmail")
            .arg("-v")
            .arg(&recipient.email)
            .stdin(sendmail_file)
            .stdout(Stdio::null())
            .status()?;

        if !status.success() {
            return Err("failed to send email".into());
        }

        Ok(())
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

        let config_data = bson::to_bson(&self.config)?;
        let config_bytes = bson::ser::to_vec(&config_data)?;
        // let config_data = serde_json::to_string_pretty(&self.config)?;
        // let config_bytes = config_data.into_bytes();
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

    // return match serde_json::from_slice(&config_bytes) {
    //     Ok(config) => Some(config),
    //     Err(e) => {
    //         error!("Error while deserializing config data: {}", e);
    //         return None;
    //     }
    // };

    return match bson::from_slice(&config_bytes) {
        Ok(config) => Some(config),
        Err(e) => {
            // Error while deserializing config file
            // TODO: This should throw flags to Overwatch and load a backed up copy of the config,
            // if possible. For now, creating a new config is fine for testing
            error!("Error while deserializing config data: {e:?}");
            // return create_config();
            return None;
        }
    };
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

            Ok(email::SMTPSettings { server, encryption })
        },
        None => {
            error!("Email address {} is invalid!", email_address);

            Err("Invalid email address")
        },
    };
}
