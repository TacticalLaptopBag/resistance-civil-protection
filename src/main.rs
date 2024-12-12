use std::io::Write;
use std::process::exit;
use std::{fs, io};
use std::fs::Permissions;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::response::Response;
use lettre::{Message, SmtpTransport, Transport};
use keyring::Entry;
use rpassword;
use serde::{Deserialize, Serialize};
use regex::Regex;
use tokio;

const CONFIG_PATH: &str = "/etc/resistance/civil-protection.conf";

const EMAIL_ADDRESS_REGEX: &str = r"\S+@\S+\.\S\S+";
const EMAIL_IDENTITY_REGEX: &str = r"^.+ <\S+@\S+\.\S\S+>$";
const EMAIL_IDENTITY_NAME_REGEX: &str = r"^.+ ";
const EMAIL_IDENTITY_ADDRESS_REGEX: &str = r" <\S+@\S+\.\S\S+>$";

#[derive(Serialize, Deserialize, Debug, Clone)]
struct EmailIdentity {
    name: String,
    email: String,
}

#[derive(Clone)]
struct EmailMessage {
    from: EmailIdentity,
    subject: String,
    body: String,
}

#[derive(Serialize, Deserialize, Debug)]
enum EmailEncryption {
    TLS,
    STARTTLS,
}

#[derive(Serialize, Deserialize, Debug)]
struct EmailSettings {
    server: String,
    encryption: EmailEncryption,
}

#[derive(Serialize, Deserialize, Debug)]
struct Config {
    email: EmailIdentity,
    email_setting: EmailSettings,
    squadmates: Vec<EmailIdentity>,
}

fn email_login(credentials: Credentials, server_config: &EmailSettings) -> Result<SmtpTransport, lettre::transport::smtp::Error> {
    let mail_builder = match server_config.encryption {
        EmailEncryption::TLS => SmtpTransport::relay(server_config.server.as_str()),
        EmailEncryption::STARTTLS => SmtpTransport::starttls_relay(server_config.server.as_str()),
    };
    let mailer = mail_builder?
        .credentials(credentials)
        .build();

    return Ok(mailer);
}

async fn email_send(mailer: SmtpTransport, message: EmailMessage, recipient: EmailIdentity) -> Result<Response, lettre::transport::smtp::Error> {
    println!("Sending mail");
    let email = Message::builder()
        .from(format!("{} <{}>", message.from.name, message.from.email).parse().unwrap())
        .to(format!("{} <{}>", recipient.name, recipient.email).parse().unwrap())
        .subject(message.subject.as_str())
        // This could be TEXT_HTML
        .header(ContentType::TEXT_PLAIN)
        .body(message.body.clone())
        .unwrap();


    return mailer.send(&email);
}

fn retrieve_password(user: &str) -> String {
    // Retrieve password from credential store
    let password_entry = Entry::new("resistance-civil-protection", user).unwrap();
    let password = match password_entry.get_password() {
        Ok(entry) => entry,
        Err(_) => {
            // Password doesn't exist yet. Prompt user for password.
            let entered_pwd = rpassword::prompt_password(format!("No password found for {}. Enter app password: ", user)).unwrap();
            match password_entry.set_password(entered_pwd.as_str()) {
                Ok(()) => println!("Saved password"),
                Err(e) => println!("Error saving password: {e:?}")
            }
            entered_pwd
        }
    };
    return password;
}

fn string_count_chars(string: &str, c: char) -> u32 {
    let mut count = 0;
    for str_char in string.chars() {
        if str_char == c {
            count += 1;
        }
    }

    return count;
}

fn prompt_email_address() -> String {
    let mut email_address = String::new();
    let mut has_ok_result = false;
    while !has_ok_result {
        print!("Enter the email address Civil Protection will send emails from: ");
        let _ = io::stdout().flush();
        has_ok_result = io::stdin().read_line(&mut email_address).is_ok();
        if !has_ok_result { continue }

        let email_identity_regex = Regex::new(EMAIL_ADDRESS_REGEX).unwrap();
        let at_count = string_count_chars(email_address.as_str(), '@');
        if at_count != 1 || !email_identity_regex.is_match(email_address.trim()) {
            has_ok_result = false;
        }
    }

    return email_address.trim().to_lowercase();
}

fn prompt_server_address() -> String {
    let mut server_address = String::new();
    let mut has_ok_result = false;
    while !has_ok_result {
        print!("Enter the outgoing SMTP address: ");
        let _ = io::stdout().flush();
        has_ok_result = io::stdin().read_line(&mut server_address).is_ok();
    }

    return server_address.to_lowercase();
}

fn prompt_server_encryption() -> EmailEncryption {
    let mut response = String::new();
    let mut response_int = 0;
    let mut has_ok_result = false;
    // TODO: Use `strum` to iterate through the enum
    // https://stackoverflow.com/a/55056427
    println!("[0]: TLS");
    println!("[1]: STARTTLS");
    while !has_ok_result {
        print!("Choose the encryption method: ");
        let _ = io::stdout().flush();
        has_ok_result = io::stdin().read_line(&mut response).is_ok();
        if !has_ok_result { continue; }

        match response.parse::<u8>() {
            Ok(int) => {
                // Can't be less than 0 since it's unsigned
                has_ok_result = int <= 1;
                if has_ok_result {
                    response_int = int;
                }
            },
            Err(_) => has_ok_result = false,
        }
    }

    return match response_int {
        0 => EmailEncryption::TLS,
        1 => EmailEncryption::STARTTLS,
        _ => panic!("Unchecked user input"),
    }
}

fn prompt_squadmate() -> Option<EmailIdentity> {
    let mut squadmate_str = String::new();
    let mut has_ok_result = false;
    while !has_ok_result {
        print!("Enter new Squadmate: ");
        let _ = io::stdout().flush();

        has_ok_result = io::stdin().read_line(&mut squadmate_str).is_ok();
        if !has_ok_result { continue; }

        if squadmate_str.to_lowercase().trim() == "done" {
            return None;
        }

        let email_identity_regex = Regex::new(EMAIL_IDENTITY_REGEX).unwrap();
        has_ok_result = email_identity_regex.is_match(squadmate_str.trim());
        if !has_ok_result {
            println!("Invalid format. Must be in the format 'Squadmate Name <email@address.com>'");
        }
    }

    let name_regex = Regex::new(EMAIL_IDENTITY_NAME_REGEX).unwrap();
    let name_match = name_regex.find(squadmate_str.trim()).unwrap();
    let name = name_match.as_str().trim();
    
    let address_regex = Regex::new(EMAIL_IDENTITY_ADDRESS_REGEX).unwrap();
    let address_match = address_regex.find(squadmate_str.trim()).unwrap();
    let address_raw = address_match.as_str();
    let address = &address_raw[2..address_raw.len()-1];
    return Some(EmailIdentity {
        name: name.to_owned(),
        email: address.to_lowercase().to_owned(),
    });
}

fn prompt_squadmates() -> Vec<EmailIdentity> {
    println!("Enter new Squadmates in the format 'Squadmate Name <email@address.com>'.");
    println!("Once done, enter 'done'.");
    let mut squadmates = vec![];
    loop {
        match prompt_squadmate() {
            Some(squadmate) => {
                println!("Added new Squadmate: {} <{}>", squadmate.name, squadmate.email);
                squadmates.push(squadmate);
            },
            None => {
                if squadmates.len() > 0 {
                    break;
                } else {
                    println!("Need to enter at least one Squadmate!");
                }
            }
        }
    }

    return squadmates;
}

fn get_server_settings_from_address(email_address: &str) -> EmailSettings {
    return match email_address.split_once("@") {
        Some((_account, domain)) => {
            let server: String;
            let encryption: EmailEncryption;
            match domain {
                "gmail.com" => {
                    server = "smtp.gmail.com".to_owned();
                    encryption = EmailEncryption::TLS;
                }
                "hotmail.com" | "outlook.com" | "msn.com" => {
                    server = "outlook.office365.com".to_owned();
                    encryption = EmailEncryption::STARTTLS;
                }
                "yahoo.com" => {
                    server = "smtp.mail.yahoo.com".to_owned();
                    encryption = EmailEncryption::TLS;
                },
                "icloud.com" => {
                    server = "smtp.mail.me.com".to_owned();
                    encryption = EmailEncryption::TLS;
                },
                "aol.com" | "verizon.net" => {
                    server = "smtp.aol.com".to_owned();
                    encryption = EmailEncryption::STARTTLS;
                },
                "comcast.net" => {
                    server = "smtp.comcast.net".to_owned();
                    encryption = EmailEncryption::TLS;
                },
                _ => {
                    server = prompt_server_address();
                    encryption = prompt_server_encryption();
                }
            }
            EmailSettings {
                server,
                encryption,
            }
        },
        None => {
            eprintln!("Email address {} is invalid!", email_address);
            exit(1);
        }
    };
}

fn create_config() -> Config {
    let email_address = prompt_email_address();
    let email_setting = get_server_settings_from_address(email_address.as_str());
    let email = EmailIdentity {
        name: "Resistance".to_owned(),
        email: email_address,
    };
    let squadmates = prompt_squadmates();

    return Config {
        email,
        email_setting,
        squadmates,
    };
}

fn load_config() -> Config {
    let config_path = Path::new(CONFIG_PATH);
    let config_bytes = fs::read(config_path);

    if config_bytes.is_err() {
        // No config file, need to prompt user
        return create_config();
    }

    return match bson::from_slice(&config_bytes.unwrap()) {
        Ok(config) => config,
        Err(e) => {
            // Error while deserializing config file
            // TODO: This should throw flags to Overwatch and load a backed up copy of the config,
            // if possible. For now, creating a new config is fine for testing
            eprintln!("Error while deserializing config data: {e:?}");
            return create_config();
        }
    };
}

fn save_config(config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    let config_path = Path::new(CONFIG_PATH);
    match config_path.parent() {
        Some(parent) => {
            fs::create_dir_all(parent)?;
            let _ = fs::set_permissions(parent, Permissions::from_mode(0o700))?;
        },
        None => panic!("Config path is either blank, or parent directory is root!"),
    }

    let config_data = bson::to_bson(&config)?;
    let config_bytes = bson::ser::to_vec(&config_data)?;
    let _ = fs::write(config_path, config_bytes)?;
    let _ = fs::set_permissions(config_path, Permissions::from_mode(0o600))?;
    
    return Ok(());
}

#[tokio::main]
async fn main() {
    let config = load_config();

    println!("Config: {:?}", config);

    println!("Logging in to email...");
    let password = retrieve_password(config.email.email.as_str());
    let creds = Credentials::new(config.email.email.to_owned(), password.to_owned());
    let mailer = match email_login(creds, &config.email_setting) {
        Ok(m) => {
            m
        },
        Err(e) => panic!("Failed to login: {e:?}"),
    };
    match mailer.test_connection() {
        Ok(_) => println!("Successfully logged in"),
        Err(e) => panic!("Failed to login: {e:?}"),
    }

    println!("Sending email to all Squadmates...");
    let message = EmailMessage {
        from: config.email.clone(),
        subject: "Test Email".to_owned(),
        body: "Confirming that email works".to_owned(),
    };

    let mut email_handles = vec![];

    for squadmate in &config.squadmates {
        // TODO: All this cloning business is bad and should be borrowed instead
        let fut = email_send(mailer.clone(), message.clone(), squadmate.clone());
        email_handles.push((squadmate.name.as_str(), tokio::spawn(fut)));
    }
    
    for (squadmate_name, handle) in email_handles {
        match handle.await.unwrap() {
            Ok(_) => println!("Email sent to {}", squadmate_name),
            Err(e) => eprintln!("Error sending email: {e:?}"),
        }
    }

    match save_config(&config) {
        Ok(_) => println!("Saved config"),
        Err(e) => eprintln!("Error saving config: {e:?}"),
    }

    // let tlb_gmail = EmailIdentity {
    //     name: "Tactical Laptop Bag".to_owned(),
    //     email: "tacticallaptopbag44@gmail.com".to_owned(),
    // };
    // let tlb_proton = EmailIdentity {
    //     name: "Tactical Laptop Bag".to_owned(),
    //     email: "tacticallaptopbag@protonmail.com".to_owned(),
    // };
    //
    // // BSON
    // let bson_gmail_serialized = bson::to_bson(&tlb_gmail).unwrap();
    // let bson_proton_serialized = bson::to_bson(&tlb_proton).unwrap();
    //
    // println!("gmail to bson = {}", bson_gmail_serialized);
    // println!("proton to bson = {}", bson_proton_serialized);
    //
    // let _ = fs::write("gmail.bson", bson::ser::to_vec(&bson_gmail_serialized).unwrap());
    // let _ = fs::write("proton.bson", bson::ser::to_vec(&bson_proton_serialized).unwrap());
    //
    // let bson_gmail_deserialized: EmailIdentity = bson::from_slice(&fs::read("gmail.bson").unwrap()).unwrap();
    // let bson_proton_deserialized: EmailIdentity = bson::from_slice(&fs::read("proton.bson").unwrap()).unwrap();
    //
    // println!("gmail from bson = {:?}", bson_gmail_deserialized);
    // println!("proton from bson = {:?}", bson_proton_deserialized);

    // Send email test
    // let password = retrieve_password(tlb_gmail.email.as_str());
    //
    // // Construct email
    // let creds = Credentials::new(tlb_gmail.email.to_owned(), password.to_owned());
    // let message = EmailMessage {
    //     from: tlb_gmail,
    //     to: tlb_proton,
    //     subject: "Email Test".to_owned(),
    //     body: "Testing email sent from Rust".to_owned(),
    // };
    //
    // // Send email
    // match send_email(message, creds) {
    //     Ok(_) => println!("Email sent."),
    //     Err(e) => println!("Failed to send mail: {e:?}"),
    // };
}
