//! TencentCloud Sign SDK for Rust
//!
//! This library provides common signing utilities for TencentCloud APIs,
//! including the TC3-HMAC-SHA256 algorithm used across all TencentCloud services.

pub mod crypto;
pub mod tc3;

pub use crypto::{hmac_sha256, hmac_sha256_hex, sha256_hex};
pub use tc3::{Tc3Signer, Tc3SignResult};
