pub mod email;
mod config;
mod cons;
mod crypt;

use email::{SMTPSettings, SendMailSettings};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{SendmailTransport, SmtpTransport, Transport};
use log::debug;
use regex::Regex;
use std::process::{Command, Stdio};
use std::io;
use config::Config;

pub struct CivilProtection {
    smtp_transport: Option<SmtpTransport>,
}

impl CivilProtection {
    pub fn new() -> CivilProtection {
        return CivilProtection {
            smtp_transport: None,
        };
    }

    pub fn is_logged_in(&self) -> bool {
        return self.smtp_transport.is_some();
    }

    pub fn login(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let conf = self.config()?;
        
        return match &conf.email_setting {
            email::Settings::SMTP(smtp_settings) => {
                let mailer = self.login_smtp(smtp_settings, &conf.email.email)?;
                self.smtp_transport = Some(mailer);
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
        let password = smtp_settings.password();

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

    pub fn add_squadmate(&mut self, squadmate: email::Identity) -> Result<(), Box<dyn std::error::Error>> {
        let mut conf = self.config()?;
        let email_regex = Regex::new(cons::EMAIL_ADDRESS_REGEX).unwrap();
        if !email_regex.is_match(&squadmate.email) {
            return Err("Invalid email format".into());
        }
        conf.squadmates.push(squadmate);
        conf.save()?;
        return Ok(());
    }

    pub fn rm_squadmate(&mut self, squadmate: &email::Identity) -> Result<bool, Box<dyn std::error::Error>> {
        let mut conf = self.config()?;
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
        conf.save()?;
        return Ok(true);
    }

    pub fn find_squadmate_by_email(&mut self, email: &str) -> Result<Option<email::Identity>, Box<dyn std::error::Error>> {
        let conf = self.config()?;
        let mut idx = 0;
        for squadmate in &conf.squadmates {
            if squadmate.email.contains(email) {
                break;
            }
            idx += 1;
        }

        if idx >= conf.squadmates.len() {
            return Ok(None);
        }

        return Ok(Some(conf.squadmates[idx].clone()));
    }

    pub fn find_squadmate_by_name(&mut self, name: &str) -> Result<Option<email::Identity>, Box<dyn std::error::Error>> {
        let conf = self.config()?;
        let mut idx = 0;
        for squadmate in &conf.squadmates {
            if squadmate.name.contains(name) {
                break;
            }
            idx += 1;
        }

        if idx >= conf.squadmates.len() {
            return Ok(None);
        }

        return Ok(Some(conf.squadmates[idx].clone()));
    }

    pub fn notify_squadmates(&self) -> Result<(), Box<dyn std::error::Error>> {
        let conf = self.config()?;
        
        let message = email::Message {
            from: conf.email.clone(),
            subject: "[Resistance] Test Email".into(),
            body: "This is a test of Resistance Civil Protection".into(),
        };

        self.send_email(&message, &conf.squadmates)?;

        return Ok(());
    }

    pub fn does_config_exist(&self) -> bool {
        Config::exists().unwrap_or(false)
    }

    pub fn delete_config(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        Config::delete()?;
        Ok(())
    }

    pub fn create_config_smtp(&mut self, identity: email::Identity, password: String) -> Result<(), Box<dyn std::error::Error>> {
        Config::new_smtp(identity, password)?;
        Ok(())
    }

    pub fn create_config_sendmail(&mut self, identity: email::Identity) -> Result<(), Box<dyn std::error::Error>> {
        Config::new_sendmail(identity)?;
        Ok(())
    }

    fn send_email(
        &self,
        message: &email::Message,
        recipients: &[email::Identity],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let conf = self.config()?;
        return match &conf.email_setting {
            email::Settings::SMTP(_) => {
                self.send_email_smtp(message, recipients)
            },
            email::Settings::SENDMAIL(_) => {
                self.send_email_sendmail(message, recipients)
            },
        };
    }

    fn send_email_smtp(
        &self,
        message: &email::Message,
        recipients: &[email::Identity],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mailer = self.check_mailer()?;

        debug!("Sending SMTP email");
        let email = message.to_lettre(recipients);
        mailer.send(&email)?;
        Ok(())
    }

    fn send_email_sendmail(
        &self,
        message: &email::Message,
        recipients: &[email::Identity],
    ) -> Result<(), Box<dyn std::error::Error>> {
        debug!("Sending sendmail email");

        let email = message.to_lettre(recipients);
        let sender = SendmailTransport::new();
        sender.send(&email)?;
        Ok(())
    }

    fn check_mailer(&self) -> Result<&SmtpTransport, &str> {
        return match &self.smtp_transport {
            Some(mailer) => Ok(mailer),
            None => Err("Not logged in"),
        };
    }

    pub fn config(&self) -> Result<Config, Box<dyn std::error::Error>> {
        return match Config::load() {
            Ok(config) => Ok(config),
            Err(_) => Err("Failed to load config".into()),
        }
    }
}

