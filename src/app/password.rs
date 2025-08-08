//! A secure password hashing and verification module using the Argon2id algorithm.

use argon2::{
    Argon2,
    password_hash::{
        Error as Argon2Error, PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng,
    },
};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum HashingError {
    #[error("Failed to hash or verify password: {0}")]
    Hash(Argon2Error),
}

#[cfg_attr(test, mockall::automock)]
pub trait Hasher: Send + Sync {
    fn hash(&self, plain: &str) -> Result<String, HashingError>;

    fn verify(&self, plain: &str, hash: &str) -> Result<bool, HashingError>;
}

pub struct Argon2Hasher<'a> {
    argon2: Argon2<'a>,
}

impl<'a> Argon2Hasher<'a> {
    pub fn new() -> Self {
        Self {
            argon2: Argon2::default(),
        }
    }
}

impl Default for Argon2Hasher<'_> {
    fn default() -> Self {
        Self::new()
    }
}

impl Hasher for Argon2Hasher<'_> {
    fn hash(&self, plain: &str) -> Result<String, HashingError> {
        let salt = SaltString::generate(&mut OsRng);

        let hash = self.argon2.hash_password(plain.as_bytes(), &salt)?.to_string();

        Ok(hash)
    }

    fn verify(&self, plain: &str, hash: &str) -> Result<bool, HashingError> {
        let parsed_hash = PasswordHash::new(hash)?;

        Ok(self
            .argon2
            .verify_password(plain.as_bytes(), &parsed_hash)
            .is_ok())
    }
}

impl From<Argon2Error> for HashingError {
    fn from(err: Argon2Error) -> Self {
        HashingError::Hash(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_verify_succeeds_for_correct_password() {
        // Arrange
        let hasher = Argon2Hasher::new();
        let password = "correct-horse-battery-staple";

        // Act
        let hashed_password = hasher.hash(password).unwrap();
        let is_valid = hasher.verify(password, &hashed_password).unwrap();

        // Assert
        assert!(is_valid);
    }

    #[test]
    fn verify_fails_for_incorrect_password() {
        // Arrange
        let hasher = Argon2Hasher::new();
        let password = "correct-horse-battery-staple";
        let wrong_password = "wrong-password";

        // Act
        let hashed_password = hasher.hash(password).unwrap();
        let is_valid = hasher.verify(wrong_password, &hashed_password).unwrap();

        // Assert
        assert!(!is_valid);
    }

    #[test]
    fn verify_returns_error_for_malformed_hash() {
        // Arrange
        let hasher = Argon2Hasher::new();
        let password = "any-password";
        let malformed_hash = "this-is-not-a-valid-argon2-hash";

        // Act
        let result = hasher.verify(password, malformed_hash);

        // Assert
        assert!(result.is_err());
        match result.err().unwrap() {
            HashingError::Hash(_) => { /* Expected error variant */ },
        }
    }

    #[test]
    fn hashes_are_unique_for_the_same_password() {
        // Arrange
        let hasher = Argon2Hasher::new();
        let password = "same-password-different-salt";

        // Act
        let hash1 = hasher.hash(password).unwrap();
        let hash2 = hasher.hash(password).unwrap();

        // Assert
        // Due to the random salt, hashing the same password twice should
        // produce two different hash strings.
        assert_ne!(hash1, hash2);

        // Both hashes should still be verifiable with the original password.
        assert!(hasher.verify(password, &hash1).unwrap());
        assert!(hasher.verify(password, &hash2).unwrap());
    }
}
