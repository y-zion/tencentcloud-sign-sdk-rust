//! Cryptographic utilities for TencentCloud signing.

use hex::encode as hex_encode;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

/// Computes SHA256 hash of the input string and returns it as a hex string.
///
/// # Arguments
/// * `data` - The input string to hash
///
/// # Returns
/// * `String` - The SHA256 hash as a hex string
///
/// # Example
/// ```rust
/// use tencentcloud_sign_sdk::sha256_hex;
/// let hash = sha256_hex("hello world");
/// assert_eq!(hash, "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
/// ```
pub fn sha256_hex(data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    let result = hasher.finalize();
    hex_encode(result)
}

/// Computes HMAC-SHA256 of the input data using the provided key.
///
/// # Arguments
/// * `key` - The HMAC key as bytes
/// * `data` - The input string to sign
///
/// # Returns
/// * `Vec<u8>` - The HMAC-SHA256 result as raw bytes
///
/// # Example
/// ```rust
/// use tencentcloud_sign_sdk::hmac_sha256;
/// let key = b"secret";
/// let data = "hello world";
/// let hmac = hmac_sha256(key, data);
/// // hmac is a Vec<u8> containing the HMAC result
/// ```
pub fn hmac_sha256(key: &[u8], data: &str) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

/// Computes HMAC-SHA256 of the input data using the provided key and returns it as a hex string.
///
/// # Arguments
/// * `key` - The HMAC key as bytes
/// * `data` - The input string to sign
///
/// # Returns
/// * `String` - The HMAC-SHA256 result as a hex string
///
/// # Example
/// ```rust
/// use tencentcloud_sign_sdk::hmac_sha256_hex;
/// let key = b"secret";
/// let data = "hello world";
/// let hmac_hex = hmac_sha256_hex(key, data);
/// // hmac_hex is a String containing the hex-encoded HMAC result
/// ```
pub fn hmac_sha256_hex(key: &[u8], data: &str) -> String {
    hex_encode(hmac_sha256(key, data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_hex() {
        let result = sha256_hex("hello world");
        assert_eq!(
            result,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_hmac_sha256() {
        let key = b"secret";
        let data = "hello world";
        let result = hmac_sha256_hex(key, data);
        // This is a known test vector for HMAC-SHA256
        assert_eq!(
            result,
            "734cc62f32841568f45715aeb9f4d7891324e6d948e4c6c60c0621cdac48623a"
        );
    }
}
