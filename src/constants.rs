use once_cell::sync::Lazy;

use crate::bn::{BigNumber, BIGNUMBER_2};

pub const LARGE_LINK_SECRET: usize = 256;
pub const LARGE_E_START: usize = 596;
pub const LARGE_E_END_RANGE: usize = 119;
pub const LARGE_PRIME: usize = 1024;
pub const LARGE_VPRIME: usize = 2128;
pub const LARGE_VPRIME_PRIME: usize = 2724;
pub const LARGE_MVECT: usize = 592;
pub const LARGE_ETILDE: usize = 456;
pub const LARGE_VTILDE: usize = 3060;
pub const LARGE_UTILDE: usize = 592;
pub const LARGE_MTILDE: usize = 593;
pub const LARGE_M2TILDE: usize = 2432;
pub const LARGE_VPRIME_TILDE: usize = 673;
pub const LARGE_RTILDE: usize = 672;
pub const ITERATION: usize = 4;
/*
  LARGE_M1_TILDE: now it differs from the paper v0.3, but author of the paper,
  Dmitry Khovratovich, suggests to use same size as LARGE_MVECT
  FIXME sync the paper and remove this comment
*/
pub const LARGE_NONCE: usize = 80; // number of bits
pub const LARGE_ALPHATILDE: usize = 2787;

// Constants that are used throughout the CL signatures code, so avoiding recomputation.
pub static LARGE_E_START_VALUE: Lazy<BigNumber> = Lazy::new(|| {
    BIGNUMBER_2
        .exp(&BigNumber::from_u32(LARGE_E_START).unwrap())
        .unwrap()
});
pub static LARGE_VPRIME_PRIME_VALUE: Lazy<BigNumber> = Lazy::new(|| {
    BIGNUMBER_2
        .exp(&BigNumber::from_u32(LARGE_VPRIME_PRIME - 1).unwrap())
        .unwrap()
});
