#![deny(missing_debug_implementations)]
#![deny(rust_2018_idioms)]
#![deny(unsafe_code)]

#[macro_use]
extern crate log;

#[macro_use]
mod error;
#[macro_use]
mod macros;
#[macro_use]
mod helpers;

mod amcl;
mod constants;
mod hash;
mod issuer;
mod prover;
mod verifier;

pub mod bn;
mod types;

pub use {
    self::error::{Error, ErrorKind},
    self::helpers::{hash_credential_attribute, new_nonce},
    self::issuer::Issuer,
    self::prover::{ProofBuilder, Prover},
    self::types::*,
    self::verifier::{ProofVerifier, Verifier},
};
