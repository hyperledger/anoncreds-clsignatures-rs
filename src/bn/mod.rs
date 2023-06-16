#[cfg_attr(feature = "openssl_bn", path = "openssl.rs")]
#[cfg_attr(not(feature = "openssl_bn"), path = "rust.rs")]
mod inner;

pub use inner::*;
