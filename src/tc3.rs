//! TC3-HMAC-SHA256 signing algorithm for TencentCloud APIs.

use crate::crypto::{hmac_sha256, hmac_sha256_hex, sha256_hex};
use time::{format_description, OffsetDateTime};

/// Result of TC3 signing containing the signature and credential scope.
#[derive(Debug, Clone, PartialEq)]
pub struct Tc3SignResult {
    /// The computed signature
    pub signature: String,
    /// The credential scope used in the signature
    pub credential_scope: String,
}

/// TC3-HMAC-SHA256 signer for TencentCloud APIs.
///
/// This signer implements the TC3-HMAC-SHA256 algorithm used by all TencentCloud services.
/// It provides a clean API for signing requests with the necessary credentials.
#[derive(Debug, Clone)]
pub struct Tc3Signer {
    secret_id: String,
    secret_key: String,
    service: String,
    debug: bool,
}

impl Tc3Signer {
    /// Creates a new TC3 signer.
    ///
    /// # Arguments
    /// * `secret_id` - TencentCloud secret ID
    /// * `secret_key` - TencentCloud secret key
    /// * `service` - The service name (e.g., "hunyuan", "cvm", etc.)
    /// * `debug` - Whether to enable debug logging
    ///
    /// # Example
    /// ```rust
    /// use tencentcloud_sign_sdk::Tc3Signer;
    /// let signer = Tc3Signer::new("your_secret_id".to_string(), "your_secret_key".to_string(), "hunyuan".to_string(), false);
    /// ```
    pub fn new(secret_id: String, secret_key: String, service: String, debug: bool) -> Self {
        Self {
            secret_id,
            secret_key,
            service,
            debug,
        }
    }

    /// Signs a request using the TC3-HMAC-SHA256 algorithm.
    ///
    /// This method implements the complete TC3 signing process:
    /// 1. Creates a canonical request
    /// 2. Creates a string to sign
    /// 3. Computes the signature using HMAC-SHA256
    ///
    /// # Arguments
    /// * `method` - HTTP method (e.g., "POST", "GET")
    /// * `canonical_uri` - Canonical URI (usually "/")
    /// * `canonical_querystring` - Canonical query string (usually empty for POST)
    /// * `canonical_headers` - Canonical headers string
    /// * `signed_headers` - List of signed headers (e.g., "content-type;host")
    /// * `hashed_payload` - SHA256 hash of the request payload
    /// * `timestamp` - Unix timestamp of the request
    ///
    /// # Returns
    /// * `Tc3SignResult` - Contains the signature and credential scope
    ///
    /// # Example
    /// ```rust
    /// use tencentcloud_sign_sdk::Tc3Signer;
    /// use time::OffsetDateTime;
    ///
    /// let signer = Tc3Signer::new("secret_id".to_string(), "secret_key".to_string(), "hunyuan".to_string(), false);
    /// let timestamp = OffsetDateTime::now_utc().unix_timestamp();
    /// let result = signer.sign(
    ///     "POST",
    ///     "/",
    ///     "",
    ///     "content-type:application/json; charset=utf-8\nhost:example.com\n",
    ///     "content-type;host",
    ///     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ///     timestamp,
    /// );
    /// ```
    pub fn sign(
        &self,
        method: &str,
        canonical_uri: &str,
        canonical_querystring: &str,
        canonical_headers: &str,
        signed_headers: &str,
        hashed_payload: &str,
        timestamp: i64,
    ) -> Tc3SignResult {
        // 1. Canonical request
        let canonical_request = format!(
            "{method}\n{uri}\n{query}\n{headers}\n{signed}\n{payload}",
            method = method,
            uri = canonical_uri,
            query = canonical_querystring,
            headers = canonical_headers,
            signed = signed_headers,
            payload = hashed_payload
        );
        let hashed_canonical_request = sha256_hex(&canonical_request);

        // 2. String to sign
        let date = OffsetDateTime::from_unix_timestamp(timestamp)
            .unwrap()
            .format(&format_description::parse("[Year]-[Month]-[Day]").unwrap())
            .unwrap();
        let credential_scope = format!("{}/{}/tc3_request", date, self.service);
        let string_to_sign = format!(
            "TC3-HMAC-SHA256\n{}\n{}\n{}",
            timestamp, credential_scope, hashed_canonical_request
        );

        // 3. Signature
        let secret_key = format!("TC3{}", self.secret_key);
        let secret_date = hmac_sha256(secret_key.as_bytes(), &date);
        let secret_service = hmac_sha256(&secret_date, &self.service);
        let secret_signing = hmac_sha256(&secret_service, "tc3_request");
        let signature = hmac_sha256_hex(&secret_signing, &string_to_sign);

        if self.debug {
            fn mask(v: &str) -> String {
                let keep = 8usize;
                if v.len() <= keep * 2 {
                    return "***".to_string();
                }
                format!("{}...{}", &v[..keep], &v[v.len() - keep..])
            }
            let string_to_sign_hash = sha256_hex(&string_to_sign);
            eprintln!(
                "[tc3-signer][sign] scope={} hashed_canonical_request={} string_to_sign_sha256={} signature={}",
                credential_scope,
                hashed_canonical_request,
                string_to_sign_hash,
                mask(&signature)
            );
        }

        Tc3SignResult {
            signature,
            credential_scope,
        }
    }

    /// Creates an Authorization header value for the signed request.
    ///
    /// # Arguments
    /// * `result` - The result from the `sign` method
    /// * `signed_headers` - The same signed headers used in signing
    ///
    /// # Returns
    /// * `String` - The complete Authorization header value
    ///
    /// # Example
    /// ```rust
    /// use tencentcloud_sign_sdk::Tc3Signer;
    /// let signer = Tc3Signer::new("secret_id".to_string(), "secret_key".to_string(), "hunyuan".to_string(), false);
    /// let result = signer.sign("POST", "/", "", "content-type:application/json\nhost:example.com\n", "content-type;host", "payload_hash", 1234567890);
    /// let auth_header = signer.create_authorization_header(&result, "content-type;host");
    /// // Returns: "TC3-HMAC-SHA256 Credential=secret_id/20231201/hunyuan/tc3_request, SignedHeaders=content-type;host, Signature=..."
    /// ```
    pub fn create_authorization_header(&self, result: &Tc3SignResult, signed_headers: &str) -> String {
        format!(
            "TC3-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
            self.secret_id, result.credential_scope, signed_headers, result.signature
        )
    }

    /// Returns the secret ID used by this signer.
    pub fn secret_id(&self) -> &str {
        &self.secret_id
    }

    /// Returns the service name used by this signer.
    pub fn service(&self) -> &str {
        &self.service
    }

    /// Returns whether debug mode is enabled.
    pub fn debug(&self) -> bool {
        self.debug
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tc3_signer_creation() {
        let signer = Tc3Signer::new(
            "test_secret_id".to_string(),
            "test_secret_key".to_string(),
            "test_service".to_string(),
            false,
        );
        assert_eq!(signer.secret_id(), "test_secret_id");
        assert_eq!(signer.service(), "test_service");
        assert_eq!(signer.debug(), false);
    }

    #[test]
    fn test_authorization_header_creation() {
        let signer = Tc3Signer::new(
            "test_secret_id".to_string(),
            "test_secret_key".to_string(),
            "test_service".to_string(),
            false,
        );
        let result = Tc3SignResult {
            signature: "test_signature".to_string(),
            credential_scope: "20231201/test_service/tc3_request".to_string(),
        };
        let auth_header = signer.create_authorization_header(&result, "content-type;host");
        assert_eq!(
            auth_header,
            "TC3-HMAC-SHA256 Credential=test_secret_id/20231201/test_service/tc3_request, SignedHeaders=content-type;host, Signature=test_signature"
        );
    }
}
