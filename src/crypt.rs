use aes_gcm::{aead::{Aead, OsRng}, AeadCore, Aes256Gcm, Key, KeyInit, Nonce};
use base64::prelude::*;

pub fn encrypt(key_bytes: &[u8], plaintext: &[u8]) -> String {
    // Take key bytes and turn it into an Aes256Gcm key
    let key = Key::<Aes256Gcm>::from_slice(key_bytes);

    // Generate a nonce (Number used only Once)
    // This is used to encrypt and decrypt the data, and is unique for every data
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    // Encrypt the plaintext
    let cipher = Aes256Gcm::new(key);
    let ciphertext = cipher.encrypt(&nonce, plaintext).unwrap();

    // Append the ciphertext to the end of the nonce for storage
    let mut cipherdata = nonce.to_vec();
    cipherdata.extend(&ciphertext);

    BASE64_STANDARD_NO_PAD.encode(cipherdata)
}

pub fn decrypt(key_bytes: &[u8], encoded_cipherdata: &String) -> Vec<u8> {
    // Take key bytes and turn it into an Aes256Gcm key
    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    
    // Extract nonce and ciphertext from encrypted data
    // Nonces are always 12 bytes long in AES 256
    let cipherdata = BASE64_STANDARD_NO_PAD.decode(encoded_cipherdata).unwrap();
    let (nonce_bytes, ciphertext) = cipherdata.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    // Decrypt ciphertext
    let cipher = Aes256Gcm::new(key);
    let plaintext = cipher.decrypt(nonce, ciphertext).unwrap();

    plaintext
}

