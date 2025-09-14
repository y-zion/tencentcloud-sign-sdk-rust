# TencentCloud Sign SDK for Rust

A common signing library for TencentCloud APIs, providing the TC3-HMAC-SHA256 algorithm used across all [TencentCloud services](https://cloud.tencent.com/document/product/382/52072).

## Features

- **TC3-HMAC-SHA256 Algorithm**: Complete implementation of TencentCloud's signing algorithm
- **Cryptographic Utilities**: SHA256 and HMAC-SHA256 functions
- **Clean API**: Easy-to-use interface for signing requests
- **Debug Support**: Optional debug logging for troubleshooting
- **No Dependencies**: Minimal dependencies for maximum compatibility

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
tencentcloud-sign-sdk = "0.1.0"
```

## Usage

### Basic Signing

```rust
use tencentcloud_sign_sdk::{Tc3Signer, sha256_hex};
use time::OffsetDateTime;

// Create a signer
let signer = Tc3Signer::new(
    "your_secret_id".to_string(),
    "your_secret_key".to_string(),
    "hunyuan".to_string(), // service name
    false, // debug mode
);

// Prepare request data
let method = "POST";
let canonical_uri = "/";
let canonical_querystring = "";
let canonical_headers = "content-type:application/json; charset=utf-8\nhost:example.com\n";
let signed_headers = "content-type;host";
let payload = r#"{"message":"hello"}"#;
let hashed_payload = sha256_hex(payload);
let timestamp = OffsetDateTime::now_utc().unix_timestamp();

// Sign the request
let result = signer.sign(
    method,
    canonical_uri,
    canonical_querystring,
    canonical_headers,
    signed_headers,
    &hashed_payload,
    timestamp,
);

// Create Authorization header
let auth_header = signer.create_authorization_header(&result, signed_headers);
```

### Cryptographic Utilities

```rust
use tencentcloud_sign_sdk::{sha256_hex, hmac_sha256_hex};

// SHA256 hashing
let hash = sha256_hex("hello world");

// HMAC-SHA256 signing
let key = b"secret_key";
let data = "message to sign";
let signature = hmac_sha256_hex(key, data);
```

## API Reference

### Tc3Signer

The main signer class for TC3-HMAC-SHA256 algorithm.

#### Methods

- `new(secret_id, secret_key, service, debug)` - Create a new signer
- `sign(...)` - Sign a request and return signature details
- `create_authorization_header(result, signed_headers)` - Create Authorization header
- `secret_id()` - Get the secret ID
- `service()` - Get the service name
- `debug()` - Check if debug mode is enabled

### Cryptographic Functions

- `sha256_hex(data)` - Compute SHA256 hash as hex string
- `hmac_sha256(key, data)` - Compute HMAC-SHA256 as raw bytes
- `hmac_sha256_hex(key, data)` - Compute HMAC-SHA256 as hex string

## License

This project uses the license provided in `LICENSE`.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
