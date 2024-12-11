use std::fs;
use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::response::Response;
use lettre::{Message, SmtpTransport, Transport};
use keyring::Entry;
use rpassword;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
struct EmailIdentity {
    name: String,
    email: String,
}

struct EmailMessage {
    from: EmailIdentity,
    to: EmailIdentity,
    subject: String,
    body: String,
}

fn send_email(message: EmailMessage, credentials: Credentials) -> Result<Response, lettre::transport::smtp::Error> {
    let email = Message::builder()
        .from(format!("{} <{}>", message.from.name, message.from.email).parse().unwrap())
        .to(format!("{} <{}>", message.to.name, message.to.email).parse().unwrap())
        .subject(message.subject)
        // This could be TEXT_HTML
        .header(ContentType::TEXT_PLAIN)
        .body(message.body)
        .unwrap();

    let mailer = SmtpTransport::relay("smtp.gmail.com")
        .unwrap()
        .credentials(credentials)
        .build();

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

fn main() {
    let tlb_gmail = EmailIdentity {
        name: "Tactical Laptop Bag".to_owned(),
        email: "tacticallaptopbag44@gmail.com".to_owned(),
    };
    let tlb_proton = EmailIdentity {
        name: "Tactical Laptop Bag".to_owned(),
        email: "tacticallaptopbag@protonmail.com".to_owned(),
    };

    // BSON
    let bson_gmail_serialized = bson::to_bson(&tlb_gmail).unwrap();
    let bson_proton_serialized = bson::to_bson(&tlb_proton).unwrap();

    println!("gmail to bson = {}", bson_gmail_serialized);
    println!("proton to bson = {}", bson_proton_serialized);

    let _ = fs::write("gmail.bson", bson::ser::to_vec(&bson_gmail_serialized).unwrap());
    let _ = fs::write("proton.bson", bson::ser::to_vec(&bson_proton_serialized).unwrap());

    let bson_gmail_deserialized: EmailIdentity = bson::from_slice(&fs::read("gmail.bson").unwrap()).unwrap();
    let bson_proton_deserialized: EmailIdentity = bson::from_slice(&fs::read("proton.bson").unwrap()).unwrap();

    println!("gmail from bson = {:?}", bson_gmail_deserialized);
    println!("proton from bson = {:?}", bson_proton_deserialized);

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
