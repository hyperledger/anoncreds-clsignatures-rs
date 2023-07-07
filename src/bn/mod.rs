use once_cell::sync::Lazy;

#[cfg_attr(feature = "openssl_bn", path = "openssl.rs")]
#[cfg_attr(not(feature = "openssl_bn"), path = "rust.rs")]
mod inner;

pub use inner::*;

// Constants that are used throughout the code, so avoiding recomputation.
pub(crate) static BIGNUMBER_1: Lazy<BigNumber> = Lazy::new(|| BigNumber::from_u32(1).unwrap());
pub(crate) static BIGNUMBER_2: Lazy<BigNumber> = Lazy::new(|| BigNumber::from_u32(2).unwrap());
