use aes::cipher::generic_array::GenericArray;
use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::aead::{Aead, OsRng};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::Engine;
use base64::engine::general_purpose;
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Encryption failed: {0}")]
    Encryption(String),

    #[error("Decryption failed: {0}")]
    Decryption(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),
}

#[cfg_attr(feature = "testing", mockall::automock)]
pub trait Crypto: Send + Sync {
    fn encrypt(&self, plaintext: &str) -> Result<String, CryptoError>;

    fn decrypt(&self, ciphertext: &str) -> Result<String, CryptoError>;
}

pub struct AesSecretCrypto {
    key: [u8; 32], // 256-bit key
}

impl AesSecretCrypto {
    pub fn new(secret: String, salt: String) -> Self {
        let mut key = [0u8; 32];

        pbkdf2_hmac::<Sha256>(
            secret.as_bytes(),
            salt.as_bytes(),
            100_000, // iterations
            &mut key,
        );

        Self { key }
    }
}

impl Crypto for AesSecretCrypto {
    fn encrypt(&self, plaintext: &str) -> Result<String, CryptoError> {
        let cipher = Aes256Gcm::new(GenericArray::from_slice(&self.key));
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_bytes())
            .map_err(|e| CryptoError::Encryption(e.to_string()))?;

        let encoded = format!(
            "{}.{}",
            general_purpose::STANDARD.encode(nonce_bytes),
            general_purpose::STANDARD.encode(ciphertext)
        );

        Ok(encoded)
    }

    fn decrypt(&self, ciphertext: &str) -> Result<String, CryptoError> {
        let cipher = Aes256Gcm::new(GenericArray::from_slice(&self.key));

        let mut parts = ciphertext.splitn(2, '.');
        let nonce_b64 = parts.next().ok_or_else(|| CryptoError::InvalidInput("Missing nonce".into()))?;
        let ct_b64 = parts
            .next()
            .ok_or_else(|| CryptoError::InvalidInput("Missing ciphertext".into()))?;

        let nonce_bytes = general_purpose::STANDARD
            .decode(nonce_b64)
            .map_err(|e| CryptoError::InvalidInput(e.to_string()))?;
        let ct_bytes = general_purpose::STANDARD
            .decode(ct_b64)
            .map_err(|e| CryptoError::InvalidInput(e.to_string()))?;

        let plaintext_bytes = cipher
            .decrypt(Nonce::from_slice(&nonce_bytes), ct_bytes.as_ref())
            .map_err(|e| CryptoError::Decryption(e.to_string()))?;

        String::from_utf8(plaintext_bytes).map_err(|e| CryptoError::Decryption(e.to_string()))
    }
}
