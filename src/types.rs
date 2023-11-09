#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::hash::Hash;
use std::iter::FromIterator;
use std::ops::RangeInclusive;

use crate::amcl::*;
use crate::bn::BigNumber;
use crate::error::Result as ClResult;
use crate::helpers;

/// A list of attributes a Credential is based on.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone)]
pub struct CredentialSchema {
    pub(crate) attrs: BTreeSet<String>, /* attr names */
}

/// A Builder of `Credential Schema`.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug)]
pub struct CredentialSchemaBuilder {
    pub(crate) attrs: BTreeSet<String>, /* attr names */
}

impl CredentialSchemaBuilder {
    pub fn new() -> ClResult<CredentialSchemaBuilder> {
        Ok(CredentialSchemaBuilder {
            attrs: BTreeSet::new(),
        })
    }

    pub fn add_attr(&mut self, attr: &str) -> ClResult<()> {
        self.attrs.insert(attr.to_owned());
        Ok(())
    }

    pub fn finalize(self) -> ClResult<CredentialSchema> {
        Ok(CredentialSchema { attrs: self.attrs })
    }
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone)]
pub struct NonCredentialSchema {
    pub(crate) attrs: BTreeSet<String>,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug)]
pub struct NonCredentialSchemaBuilder {
    pub(crate) attrs: BTreeSet<String>,
}

impl NonCredentialSchemaBuilder {
    pub fn new() -> ClResult<NonCredentialSchemaBuilder> {
        Ok(NonCredentialSchemaBuilder {
            attrs: BTreeSet::new(),
        })
    }

    pub fn add_attr(&mut self, attr: &str) -> ClResult<()> {
        self.attrs.insert(attr.to_owned());
        Ok(())
    }

    pub fn finalize(self) -> ClResult<NonCredentialSchema> {
        Ok(NonCredentialSchema { attrs: self.attrs })
    }
}

/// The m value for attributes,
/// commitments also store a blinding factor
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Eq, PartialEq)]
pub enum CredentialValue {
    Known {
        value: BigNumber,
    }, //Issuer and Prover know these
    Hidden {
        value: BigNumber,
    }, //Only known to Prover who binds these into the U factor
    Commitment {
        value: BigNumber,
        blinding_factor: BigNumber,
    }, //Only known to Prover, not included in the credential, used for proving knowledge during issuance
}

impl CredentialValue {
    pub fn try_clone(&self) -> ClResult<CredentialValue> {
        Ok(match *self {
            CredentialValue::Known { ref value } => CredentialValue::Known {
                value: value.try_clone()?,
            },
            CredentialValue::Hidden { ref value } => CredentialValue::Hidden {
                value: value.try_clone()?,
            },
            CredentialValue::Commitment {
                ref value,
                ref blinding_factor,
            } => CredentialValue::Commitment {
                value: value.try_clone()?,
                blinding_factor: blinding_factor.try_clone()?,
            },
        })
    }

    pub fn is_known(&self) -> bool {
        matches!(*self, CredentialValue::Known { .. })
    }

    pub fn is_hidden(&self) -> bool {
        matches!(*self, CredentialValue::Hidden { .. })
    }

    pub fn is_commitment(&self) -> bool {
        matches!(*self, CredentialValue::Commitment { .. })
    }

    pub fn value(&self) -> &BigNumber {
        match *self {
            CredentialValue::Known { ref value } => value,
            CredentialValue::Hidden { ref value } => value,
            CredentialValue::Commitment { ref value, .. } => value,
        }
    }
}

/// Values of attributes from `Claim Schema` (must be integers).
#[derive(Debug, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CredentialValues {
    pub(crate) attrs_values: BTreeMap<String, CredentialValue>,
}

impl CredentialValues {
    pub fn merge(&self, values: &Self) -> ClResult<CredentialValues> {
        let mut vals = self.try_clone()?;
        let mut add = values.try_clone()?;
        vals.attrs_values.append(&mut add.attrs_values);
        Ok(vals)
    }

    pub fn try_clone(&self) -> ClResult<CredentialValues> {
        Ok(CredentialValues {
            attrs_values: helpers::clone_credential_value_map(&self.attrs_values)?,
        })
    }
}

/// A Builder of `Credential Values`.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug)]
pub struct CredentialValuesBuilder {
    pub(crate) attrs_values: BTreeMap<String, CredentialValue>, /* attr_name -> int representation of value */
}

impl CredentialValuesBuilder {
    pub fn new() -> ClResult<CredentialValuesBuilder> {
        Ok(CredentialValuesBuilder {
            attrs_values: BTreeMap::new(),
        })
    }

    pub fn add_dec_known(&mut self, attr: &str, value: &str) -> ClResult<()> {
        self.attrs_values.insert(
            attr.to_owned(),
            CredentialValue::Known {
                value: BigNumber::from_dec(value)?,
            },
        );
        Ok(())
    }

    pub fn add_dec_hidden(&mut self, attr: &str, value: &str) -> ClResult<()> {
        self.attrs_values.insert(
            attr.to_owned(),
            CredentialValue::Hidden {
                value: BigNumber::from_dec(value)?,
            },
        );
        Ok(())
    }

    pub fn add_dec_commitment(
        &mut self,
        attr: &str,
        value: &str,
        blinding_factor: &str,
    ) -> ClResult<()> {
        self.attrs_values.insert(
            attr.to_owned(),
            CredentialValue::Commitment {
                value: BigNumber::from_dec(value)?,
                blinding_factor: BigNumber::from_dec(blinding_factor)?,
            },
        );
        Ok(())
    }

    pub fn add_value_known(&mut self, attr: &str, value: &BigNumber) -> ClResult<()> {
        self.attrs_values.insert(
            attr.to_owned(),
            CredentialValue::Known {
                value: value.try_clone()?,
            },
        );
        Ok(())
    }

    pub fn add_value_hidden(&mut self, attr: &str, value: &BigNumber) -> ClResult<()> {
        self.attrs_values.insert(
            attr.to_owned(),
            CredentialValue::Hidden {
                value: value.try_clone()?,
            },
        );
        Ok(())
    }

    pub fn add_value_commitment(
        &mut self,
        attr: &str,
        value: &BigNumber,
        blinding_factor: &BigNumber,
    ) -> ClResult<()> {
        self.attrs_values.insert(
            attr.to_owned(),
            CredentialValue::Commitment {
                value: value.try_clone()?,
                blinding_factor: blinding_factor.try_clone()?,
            },
        );
        Ok(())
    }

    pub fn finalize(self) -> ClResult<CredentialValues> {
        Ok(CredentialValues {
            attrs_values: self.attrs_values,
        })
    }
}

/// `Issuer Public Key` contains 2 internal parts.
/// One for signing primary credentials and second for signing non-revocation credentials.
/// These keys are used to proof that credential was issued and doesn’t revoked by this issuer.
/// Issuer keys have global identifier that must be known to all parties.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, PartialEq)]
pub struct CredentialPublicKey {
    pub(crate) p_key: CredentialPrimaryPublicKey,
    pub(crate) r_key: Option<CredentialRevocationPublicKey>,
}

impl CredentialPublicKey {
    pub fn try_clone(&self) -> ClResult<CredentialPublicKey> {
        Ok(CredentialPublicKey {
            p_key: self.p_key.try_clone()?,
            r_key: self.r_key.clone(),
        })
    }

    pub fn get_primary_key(&self) -> &CredentialPrimaryPublicKey {
        &self.p_key
    }

    pub fn get_revocation_key(&self) -> Option<&CredentialRevocationPublicKey> {
        self.r_key.as_ref()
    }

    pub fn build_from_parts(
        p_key: &CredentialPrimaryPublicKey,
        r_key: Option<&CredentialRevocationPublicKey>,
    ) -> ClResult<CredentialPublicKey> {
        Ok(CredentialPublicKey {
            p_key: p_key.try_clone()?,
            r_key: r_key.cloned(),
        })
    }
}

/// `Issuer Private Key`: contains 2 internal parts.
/// One for signing primary credentials and second for signing non-revocation credentials.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug)]
pub struct CredentialPrivateKey {
    pub(crate) p_key: CredentialPrimaryPrivateKey,
    pub(crate) r_key: Option<CredentialRevocationPrivateKey>,
}

/// Issuer's "Public Key" is used to verify the Issuer's signature over the Credential's attributes' values (primary credential).
#[cfg_attr(feature = "serde", derive(Serialize))]
#[derive(Debug, PartialEq)]
pub struct CredentialPrimaryPublicKey {
    pub(crate) n: BigNumber,
    pub(crate) s: BigNumber,
    pub(crate) r: HashMap<String /* attr_name */, BigNumber>,
    pub(crate) rctxt: BigNumber,
    pub(crate) z: BigNumber,
}

impl CredentialPrimaryPublicKey {
    pub fn try_clone(&self) -> ClResult<CredentialPrimaryPublicKey> {
        Ok(CredentialPrimaryPublicKey {
            n: self.n.try_clone()?,
            s: self.s.try_clone()?,
            r: helpers::clone_bignum_map(&self.r)?,
            rctxt: self.rctxt.try_clone()?,
            z: self.z.try_clone()?,
        })
    }
}

#[cfg(feature = "serde")]
impl<'a> ::serde::de::Deserialize<'a> for CredentialPrimaryPublicKey {
    fn deserialize<D: ::serde::de::Deserializer<'a>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct CredentialPrimaryPublicKeyV1 {
            n: BigNumber,
            s: BigNumber,
            r: HashMap<String /* attr_name */, BigNumber>,
            rctxt: BigNumber,
            #[serde(default)]
            rms: BigNumber,
            z: BigNumber,
        }

        let mut helper = CredentialPrimaryPublicKeyV1::deserialize(deserializer)?;
        if helper.rms != BigNumber::default() {
            helper.r.insert("master_secret".to_string(), helper.rms);
        }
        Ok(CredentialPrimaryPublicKey {
            n: helper.n,
            s: helper.s,
            rctxt: helper.rctxt,
            z: helper.z,
            r: helper.r,
        })
    }
}

/// Issuer's "Private Key" used for signing Credential's attributes' values (primary credential)
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, PartialEq)]
pub struct CredentialPrimaryPrivateKey {
    pub(crate) p: BigNumber,
    pub(crate) q: BigNumber,
}

/// `Primary Public Key Metadata` required for building of Proof Correctness of `Issuer Public Key`
#[derive(Debug)]
pub struct CredentialPrimaryPublicKeyMetadata {
    pub(crate) xz: BigNumber,
    pub(crate) xr: HashMap<String, BigNumber>,
}

/// Proof of `Issuer Public Key` correctness
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, PartialEq)]
pub struct CredentialKeyCorrectnessProof {
    pub(crate) c: BigNumber,
    pub(crate) xz_cap: BigNumber,
    pub(crate) xr_cap: Vec<(String, BigNumber)>,
}

impl CredentialKeyCorrectnessProof {
    pub fn try_clone(&self) -> ClResult<CredentialKeyCorrectnessProof> {
        Ok(CredentialKeyCorrectnessProof {
            c: self.c.try_clone()?,
            xz_cap: self.xz_cap.try_clone()?,
            xr_cap: self.xr_cap.iter().try_fold(vec![], |mut acc, (s, bn)| {
                acc.push((s.clone(), bn.try_clone()?));
                ClResult::Ok(acc)
            })?,
        })
    }
}

/// `Revocation Public Key` is used to verify that credential wasn't revoked by Issuer.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq)]
pub struct CredentialRevocationPublicKey {
    pub(crate) g: PointG1,
    pub(crate) g_dash: PointG2,
    pub(crate) h: PointG1,
    pub(crate) h0: PointG1,
    pub(crate) h1: PointG1,
    pub(crate) h2: PointG1,
    pub(crate) htilde: PointG1,
    pub(crate) h_cap: PointG2,
    pub(crate) u: PointG2,
    pub(crate) pk: PointG1,
    pub(crate) y: PointG2,
}

/// `Revocation Private Key` is used for signing Credential.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug)]
pub struct CredentialRevocationPrivateKey {
    pub(crate) x: GroupOrderElement,
    pub(crate) sk: GroupOrderElement,
}

/// Accumulator value, contained in a revocation registry and delta.
#[derive(Debug, Copy, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(transparent))]
pub struct Accumulator(PointG2Inf);

impl Accumulator {
    pub const BYTES_REPR_SIZE: usize = PointG2Inf::BYTES_REPR_SIZE;

    /// Create a new empty accumulator (represented by the infinity point).
    pub fn new_inf() -> ClResult<Self> {
        Ok(PointG2Inf::new_inf()?.into())
    }

    /// Check if the accumulator is the infinity point.
    pub fn is_inf(&self) -> ClResult<bool> {
        self.0.is_inf()
    }

    /// Decode from hexadecimal format
    pub fn from_string(s: &str) -> ClResult<Self> {
        PointG2Inf::from_string(s).map(Self)
    }

    /// Encode to hexadecimal format
    pub fn to_string(&self) -> ClResult<String> {
        self.0.to_string()
    }

    /// Encode to binary format (big-endian)
    pub fn to_bytes(&self) -> ClResult<Vec<u8>> {
        self.0 .0.to_bytes()
    }

    /// Decode from binary format (big-endian)
    pub fn from_bytes(b: &[u8]) -> ClResult<Self> {
        Ok(PointG2::from_bytes(b)?.into())
    }
}

impl From<PointG2> for Accumulator {
    fn from(value: PointG2) -> Self {
        Self(value.into())
    }
}

impl From<PointG2Inf> for Accumulator {
    fn from(value: PointG2Inf) -> Self {
        Self(value)
    }
}

impl AsRef<PointG2> for Accumulator {
    fn as_ref(&self) -> &PointG2 {
        &self.0 .0
    }
}

/// `Revocation Registry` contains accumulator.
/// Must be published by Issuer on a tamper-evident and highly available storage.
/// Used by prover to prove that a credential hasn't revoked by the issuer.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq)]
pub struct RevocationRegistry {
    pub accum: Accumulator,
}

impl RevocationRegistry {
    /// Create the initial revocation registry state.
    pub fn initial_state(
        credential_pub_key: &CredentialPublicKey,
        rev_key_priv: &RevocationKeyPrivate,
        max_cred_num: u32,
        issuance_by_default: bool,
    ) -> ClResult<Self> {
        let cred_rev_pub_key: &CredentialRevocationPublicKey =
            credential_pub_key.r_key.as_ref().ok_or_else(|| {
                err_msg!("There are no revocation keys in the credential public key.")
            })?;
        Self::_initial_state(
            cred_rev_pub_key,
            rev_key_priv,
            max_cred_num,
            issuance_by_default,
        )
    }

    pub(crate) fn _initial_state(
        cred_rev_pub_key: &CredentialRevocationPublicKey,
        rev_key_priv: &RevocationKeyPrivate,
        max_cred_num: u32,
        issuance_by_default: bool,
    ) -> ClResult<Self> {
        trace!("RevocationRegistry::_initial_state: >>> cred_rev_pub_key: {:?}, rev_key_priv: {:?}, max_cred_num: {:?}, issuance_by_default: {:?}",
               cred_rev_pub_key, secret!(rev_key_priv), max_cred_num, issuance_by_default);

        let accum = if issuance_by_default {
            Tail::accum_range(
                &cred_rev_pub_key.g_dash,
                &rev_key_priv.gamma,
                1..=max_cred_num,
            )?
        } else {
            Accumulator::new_inf()?
        };
        let rev_reg = Self { accum };

        trace!(
            "RevocationRegistry::_initial_state: <<< rev_reg: {:?}",
            rev_reg
        );

        Ok(rev_reg)
    }

    /// Create the revocation registry for a set of issued credential indexes.
    pub fn for_issued(
        credential_pub_key: &CredentialPublicKey,
        rev_key_priv: &RevocationKeyPrivate,
        max_cred_num: u32,
        issued: &BTreeSet<u32>,
    ) -> ClResult<Self> {
        trace!("RevocationRegistry::for_issued: >>> credential_pub_key: {:?}, rev_key_priv: {:?}, max_cred_num: {:?}, issued: {:?}",
        credential_pub_key, secret!(rev_key_priv), max_cred_num, issued);

        let cred_rev_pub_key: &CredentialRevocationPublicKey =
            credential_pub_key.r_key.as_ref().ok_or_else(|| {
                err_msg!("There are no revocation keys in the credential public key.")
            })?;
        if let Some(first) = issued.iter().next().copied() {
            if first == 0 {
                return Err(err_msg!("Invalid revocation index, 0."));
            }
        }
        if let Some(last) = issued.iter().last().copied() {
            if last > max_cred_num {
                return Err(err_msg!("Invalid revocation index, exceeds max_cred_num."));
            }
        }

        let rev_reg = Self {
            accum: Tail::accum_indexes(&cred_rev_pub_key.g_dash, &rev_key_priv.gamma, issued)?,
        };

        trace!("RevocationRegistry::for_issued: <<< rev_reg: {:?}", rev_reg);
        Ok(rev_reg)
    }
}

impl From<Accumulator> for RevocationRegistry {
    fn from(accum: Accumulator) -> RevocationRegistry {
        RevocationRegistry { accum }
    }
}

impl From<RevocationRegistryDelta> for RevocationRegistry {
    fn from(rev_reg_delta: RevocationRegistryDelta) -> RevocationRegistry {
        RevocationRegistry {
            accum: rev_reg_delta.accum,
        }
    }
}

impl From<&RevocationRegistry> for RevocationRegistryDelta {
    fn from(rev_reg: &RevocationRegistry) -> RevocationRegistryDelta {
        RevocationRegistryDelta::from_parts(None, rev_reg, &HashSet::new(), &HashSet::new())
    }
}

/// `Revocation Registry Delta` contains Accumulator changes.
/// Must be applied to `Revocation Registry`
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct RevocationRegistryDelta {
    #[cfg_attr(
        feature = "serde",
        serde(default),
        serde(skip_serializing_if = "Option::is_none")
    )]
    pub(crate) prev_accum: Option<Accumulator>,
    pub(crate) accum: Accumulator,
    #[cfg_attr(
        feature = "serde",
        serde(default),
        serde(skip_serializing_if = "HashSet::is_empty")
    )]
    pub(crate) issued: HashSet<u32>,
    #[cfg_attr(
        feature = "serde",
        serde(default),
        serde(skip_serializing_if = "HashSet::is_empty")
    )]
    pub(crate) revoked: HashSet<u32>,
}

impl RevocationRegistryDelta {
    pub fn from_parts(
        rev_reg_from: Option<&RevocationRegistry>,
        rev_reg_to: &RevocationRegistry,
        issued: &HashSet<u32>,
        revoked: &HashSet<u32>,
    ) -> RevocationRegistryDelta {
        RevocationRegistryDelta {
            prev_accum: rev_reg_from.map(|rev_reg| rev_reg.accum),
            accum: rev_reg_to.accum,
            issued: issued.clone(),
            revoked: revoked.clone(),
        }
    }

    pub fn merge(&mut self, other_delta: &RevocationRegistryDelta) -> ClResult<()> {
        if other_delta.prev_accum.is_none() || self.accum != other_delta.prev_accum.unwrap() {
            return Err(err_msg!("Deltas can not be merged."));
        }

        self.accum = other_delta.accum;

        self.issued
            .extend(other_delta.issued.difference(&self.revoked));

        self.revoked
            .extend(other_delta.revoked.difference(&self.issued));

        for index in other_delta.revoked.iter() {
            self.issued.remove(index);
        }

        for index in other_delta.issued.iter() {
            self.revoked.remove(index);
        }

        Ok(())
    }
}

/// `Revocation Key Public` Accumulator public key.
/// Must be published together with Accumulator
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone)]
pub struct RevocationKeyPublic {
    pub(crate) z: Pair,
}

/// `Revocation Key Private` Accumulator primate key.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug)]
pub struct RevocationKeyPrivate {
    pub(crate) gamma: GroupOrderElement,
}

/// `Tail` point of curve used to update an accumulator.
#[derive(Debug, Copy, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(transparent))]
pub struct Tail(PointG2);

impl Tail {
    pub const BYTES_REPR_SIZE: usize = PointG2::BYTES_REPR_SIZE;

    /// Decode from hexadecimal format
    pub fn from_string(s: &str) -> ClResult<Self> {
        PointG2::from_string(s).map(Self)
    }

    /// Encode to hexadecimal format
    pub fn to_string(&self) -> ClResult<String> {
        self.0.to_string()
    }

    /// Encode to binary format (big-endian)
    pub fn to_bytes(&self) -> ClResult<Vec<u8>> {
        self.0.to_bytes()
    }

    /// Decode from binary format (big-endian)
    pub fn from_bytes(b: &[u8]) -> ClResult<Self> {
        PointG2::from_bytes(b).map(Self)
    }
}

impl From<PointG2> for Tail {
    fn from(value: PointG2) -> Self {
        Self(value)
    }
}

impl AsRef<PointG2> for Tail {
    fn as_ref(&self) -> &PointG2 {
        &self.0
    }
}

impl Tail {
    pub(crate) fn new(index: u32, g_dash: &PointG2, gamma: &GroupOrderElement) -> ClResult<Self> {
        g_dash.mul(&Self::index_pow(index, gamma)?).map(Self)
    }

    pub(crate) fn index_pow(index: u32, gamma: &GroupOrderElement) -> ClResult<GroupOrderElement> {
        gamma.pow_mod(&GroupOrderElement::new_u32(index)?)
    }

    pub(crate) fn accum_range(
        g_dash: &PointG2,
        gamma: &GroupOrderElement,
        range: RangeInclusive<u32>,
    ) -> ClResult<Accumulator> {
        let (mut start, mut end) = range.into_inner();
        if start > end {
            std::mem::swap(&mut start, &mut end);
        }
        let mut pow = Self::index_pow(start, gamma)?;
        let mut acc = pow;
        while start < end {
            pow = pow.mul_mod(gamma)?;
            acc = acc.add_mod(&pow)?;
            start += 1;
        }
        Ok(g_dash.mul(&acc)?.into())
    }

    pub(crate) fn accum_indexes(
        g_dash: &PointG2,
        gamma: &GroupOrderElement,
        indexes: &BTreeSet<u32>,
    ) -> ClResult<Accumulator> {
        let mut acc = GroupOrderElement::zero()?;
        let mut base = *gamma;
        let mut pow = 1;
        for idx in indexes.iter().copied() {
            if idx == 0 {
                continue; // skip invalid index
            } else if idx != pow {
                let diff = idx - pow;
                if diff == 1 {
                    base = base.mul_mod(gamma)?;
                } else {
                    base = base.mul_mod(&Self::index_pow(diff, gamma)?)?;
                }
                pow = idx;
            }
            acc = acc.add_mod(&base)?;
        }
        Ok(g_dash.mul(&acc)?.into())
    }
}

/// Generator of `Tail's`.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone)]
pub struct RevocationTailsGenerator {
    size: u32,
    current_index: u32,
    g_dash: PointG2,
    gamma: GroupOrderElement,
    cur: Option<PointG2>,
}

impl RevocationTailsGenerator {
    pub(crate) fn new(max_cred_num: u32, gamma: GroupOrderElement, g_dash: PointG2) -> Self {
        RevocationTailsGenerator {
            size: 2 * max_cred_num + 1, // Unused 0th + valuable 1..L + secret (L+1)th + valuable (L+2)..(2L-1)
            current_index: 0,
            gamma,
            g_dash,
            cur: None,
        }
    }

    pub fn count(&self) -> u32 {
        self.size - self.current_index
    }

    pub fn try_next(&mut self) -> ClResult<Option<Tail>> {
        if self.current_index >= self.size {
            Ok(None)
        } else {
            let mut res = if let Some(cur) = self.cur.as_ref() {
                cur.mul(&self.gamma)?
            } else {
                self.g_dash
            };
            self.cur.replace(res);
            if self.current_index == (self.size / 2) + 1 {
                // Do not output tail index n+1
                res = self.g_dash;
            }
            self.current_index += 1;
            Ok(Some(Tail(res)))
        }
    }
}

pub trait RevocationTailsAccessor {
    fn access_tail(&self, tail_id: u32, accessor: &mut dyn FnMut(&Tail)) -> ClResult<()>;
}

/// Simple implementation of `RevocationTailsAccessor` that stores all tails as BTreeMap.
#[derive(Debug, Clone)]
pub struct SimpleTailsAccessor {
    tails: Vec<Tail>,
}

impl RevocationTailsAccessor for SimpleTailsAccessor {
    fn access_tail(&self, tail_id: u32, accessor: &mut dyn FnMut(&Tail)) -> ClResult<()> {
        accessor(&self.tails[tail_id as usize]);
        Ok(())
    }
}

impl SimpleTailsAccessor {
    pub fn new(
        rev_tails_generator: &mut RevocationTailsGenerator,
    ) -> ClResult<SimpleTailsAccessor> {
        let mut tails: Vec<Tail> = Vec::new();
        while let Some(tail) = rev_tails_generator.try_next()? {
            tails.push(tail);
        }
        Ok(SimpleTailsAccessor { tails })
    }
}

/// Issuer's signature over Credential attribute values.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, PartialEq)]
pub struct CredentialSignature {
    pub(crate) p_credential: PrimaryCredentialSignature,
    pub(crate) r_credential: Option<NonRevocationCredentialSignature>, /* will be used to proof is credential revoked preparation */
}

impl CredentialSignature {
    pub fn extract_index(&self) -> Option<u32> {
        self.r_credential
            .as_ref()
            .map(|r_credential| r_credential.i)
    }

    pub fn try_clone(&self) -> ClResult<CredentialSignature> {
        Ok(CredentialSignature {
            p_credential: self.p_credential.try_clone()?,
            r_credential: self.r_credential.as_ref().cloned(),
        })
    }
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, PartialEq, Eq)]
pub struct PrimaryCredentialSignature {
    pub(crate) m_2: BigNumber,
    pub(crate) a: BigNumber,
    pub(crate) e: BigNumber,
    pub(crate) v: BigNumber,
}

impl PrimaryCredentialSignature {
    pub fn try_clone(&self) -> ClResult<PrimaryCredentialSignature> {
        Ok(PrimaryCredentialSignature {
            m_2: self.m_2.try_clone()?,
            a: self.a.try_clone()?,
            e: self.e.try_clone()?,
            v: self.v.try_clone()?,
        })
    }
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, PartialEq, Clone)]
pub struct NonRevocationCredentialSignature {
    pub(crate) sigma: PointG1,
    pub(crate) c: GroupOrderElement,
    pub(crate) vr_prime_prime: GroupOrderElement,
    pub(crate) witness_signature: WitnessSignature,
    pub(crate) g_i: PointG1,
    pub(crate) i: u32,
    pub(crate) m2: GroupOrderElement,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, PartialEq, Eq)]
pub struct SignatureCorrectnessProof {
    pub(crate) se: BigNumber,
    pub(crate) c: BigNumber,
}

impl SignatureCorrectnessProof {
    pub fn try_clone(&self) -> ClResult<SignatureCorrectnessProof> {
        Ok(SignatureCorrectnessProof {
            se: self.se.try_clone()?,
            c: self.c.try_clone()?,
        })
    }
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq)]
pub struct Witness {
    pub(crate) omega: PointG2Inf,
}

impl Witness {
    pub fn new<RTA>(
        rev_idx: u32,
        max_cred_num: u32,
        issuance_by_default: bool,
        rev_reg_delta: &RevocationRegistryDelta,
        rev_tails_accessor: &RTA,
    ) -> ClResult<Witness>
    where
        RTA: RevocationTailsAccessor,
    {
        trace!("Witness::new: >>> rev_idx: {:?}, max_cred_num: {:?}, issuance_by_default: {:?}, rev_reg_delta: {:?}",
               rev_idx, max_cred_num, issuance_by_default, rev_reg_delta);

        if rev_idx == 0 || rev_idx > max_cred_num {
            return Err(err_msg!("Revocation index is outside of valid range"));
        }

        let mut omega = PointG2::new_inf()?;

        let mut issued = Self::issued_indices(max_cred_num, issuance_by_default, rev_reg_delta);
        issued.remove(&rev_idx);

        for j in issued.into_iter().rev() {
            let index = max_cred_num + 1 - j + rev_idx;
            rev_tails_accessor.access_tail(index, &mut |tail| {
                omega = omega.add(&tail.0).unwrap();
            })?;
        }

        let witness = Witness {
            omega: omega.into(),
        };

        trace!("Witness::new: <<< witness: {:?}", witness);

        Ok(witness)
    }

    pub fn update<RTA>(
        &mut self,
        rev_idx: u32,
        max_cred_num: u32,
        rev_reg_delta: &RevocationRegistryDelta,
        rev_tails_accessor: &RTA,
    ) -> ClResult<()>
    where
        RTA: RevocationTailsAccessor,
    {
        trace!(
            "Witness::update: >>> rev_idx: {:?}, max_cred_num: {:?}, rev_reg_delta: {:?}",
            rev_idx,
            max_cred_num,
            rev_reg_delta
        );

        if rev_idx == 0 || rev_idx > max_cred_num {
            return Err(err_msg!("Revocation index is outside of valid range"));
        }

        let mut indexes = BTreeMap::new();
        for j in rev_reg_delta.issued.iter() {
            indexes.insert(*j, true);
        }
        for j in rev_reg_delta.revoked.iter() {
            indexes.insert(*j, false);
        }

        let mut new_omega = self.omega.0;
        for (j, add) in indexes.into_iter().rev() {
            if rev_idx == 0 || rev_idx == j || rev_idx > max_cred_num {
                continue;
            }
            let index = max_cred_num + 1 - j + rev_idx;
            rev_tails_accessor.access_tail(index, &mut |tail| {
                new_omega = if add {
                    new_omega.add(&tail.0)
                } else {
                    new_omega.sub(&tail.0)
                }
                .unwrap()
            })?;
        }

        self.omega = new_omega.into();

        trace!("Witness::update: <<<");

        Ok(())
    }

    fn issued_indices(
        max_cred_num: u32,
        issuance_by_default: bool,
        rev_reg_delta: &RevocationRegistryDelta,
    ) -> BTreeSet<u32> {
        if issuance_by_default {
            (1..=max_cred_num)
                .filter(|idx| !rev_reg_delta.revoked.contains(idx))
                .collect::<BTreeSet<u32>>()
        } else {
            BTreeSet::from_iter(rev_reg_delta.issued.iter().cloned())
        }
    }
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, PartialEq, Clone)]
pub struct WitnessSignature {
    pub(crate) sigma_i: PointG2,
    pub(crate) u_i: PointG2,
    pub(crate) g_i: PointG1,
}

/// Secret key encoded in a credential that is used to prove that prover owns the credential; can be used to
/// prove linkage across credentials.
/// Prover blinds link secret, generating `BlindedCredentialSecrets` and `CredentialSecretsBlindingFactors` (blinding factors)
/// and sends the `BlindedCredentialSecrets` to Issuer who then encodes it credential creation.
/// The blinding factors are used by Prover for post processing of issued credentials.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug)]
pub struct LinkSecret {
    pub(crate) ms: BigNumber,
}

impl LinkSecret {
    pub fn value(&self) -> ClResult<BigNumber> {
        self.ms.try_clone()
    }

    pub fn try_clone(&self) -> ClResult<LinkSecret> {
        Ok(Self { ms: self.value()? })
    }
}

impl AsRef<BigNumber> for LinkSecret {
    fn as_ref(&self) -> &BigNumber {
        &self.ms
    }
}

impl From<BigNumber> for LinkSecret {
    fn from(ms: BigNumber) -> Self {
        Self { ms }
    }
}

impl From<LinkSecret> for BigNumber {
    fn from(sec: LinkSecret) -> Self {
        sec.ms
    }
}

/// Blinded Master Secret uses by Issuer in credential creation.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug)]
pub struct BlindedCredentialSecrets {
    pub(crate) u: BigNumber,
    pub(crate) ur: Option<PointG1>,
    pub(crate) hidden_attributes: BTreeSet<String>,
    pub(crate) committed_attributes: BTreeMap<String, BigNumber>,
}

impl BlindedCredentialSecrets {
    pub fn try_clone(&self) -> ClResult<Self> {
        Ok(Self {
            u: self.u.try_clone()?,
            ur: self.ur,
            hidden_attributes: self.hidden_attributes.clone(),
            committed_attributes: helpers::clone_bignum_btreemap(&self.committed_attributes)?,
        })
    }
}

/// `CredentialSecretsBlindingFactors` used by Prover for post processing of credentials received from Issuer.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug)]
pub struct CredentialSecretsBlindingFactors {
    pub(crate) v_prime: BigNumber,
    pub(crate) vr_prime: Option<GroupOrderElement>,
}

impl CredentialSecretsBlindingFactors {
    pub fn try_clone(&self) -> ClResult<Self> {
        Ok(Self {
            v_prime: self.v_prime.try_clone()?,
            vr_prime: self.vr_prime,
        })
    }
}

#[derive(Eq, PartialEq, Debug)]
pub struct PrimaryBlindedCredentialSecretsFactors {
    pub(crate) u: BigNumber,
    pub(crate) v_prime: BigNumber,
    pub(crate) hidden_attributes: BTreeSet<String>,
    pub(crate) committed_attributes: BTreeMap<String, BigNumber>,
}

#[derive(Debug)]
pub struct RevocationBlindedCredentialSecretsFactors {
    pub(crate) ur: PointG1,
    pub(crate) vr_prime: GroupOrderElement,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Eq, PartialEq)]
pub struct BlindedCredentialSecretsCorrectnessProof {
    pub(crate) c: BigNumber,                        // Fiat-Shamir challenge hash
    pub(crate) v_dash_cap: BigNumber, // Value to prove knowledge of `u` construction in `BlindedCredentialSecrets`
    pub(crate) m_caps: BTreeMap<String, BigNumber>, // Values for proving knowledge of committed values
    pub(crate) r_caps: BTreeMap<String, BigNumber>, // Blinding values for m_caps
}

impl BlindedCredentialSecretsCorrectnessProof {
    pub fn try_clone(&self) -> ClResult<Self> {
        Ok(Self {
            c: self.c.try_clone()?,
            v_dash_cap: self.v_dash_cap.try_clone()?,
            m_caps: helpers::clone_bignum_btreemap(&self.m_caps)?,
            r_caps: helpers::clone_bignum_btreemap(&self.r_caps)?,
        })
    }
}

/// “Sub Proof Request” - input to create a Proof for a credential;
/// Contains attributes to be revealed and predicates.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
pub struct SubProofRequest {
    pub(crate) revealed_attrs: BTreeSet<String>,
    pub(crate) predicates: BTreeSet<Predicate>,
}

/// Builder of “Sub Proof Request”.
#[derive(Debug)]
pub struct SubProofRequestBuilder {
    value: SubProofRequest,
}

impl SubProofRequestBuilder {
    pub fn new() -> ClResult<SubProofRequestBuilder> {
        Ok(SubProofRequestBuilder {
            value: SubProofRequest {
                revealed_attrs: BTreeSet::new(),
                predicates: BTreeSet::new(),
            },
        })
    }

    pub fn add_revealed_attr(&mut self, attr: &str) -> ClResult<()> {
        self.value.revealed_attrs.insert(attr.to_owned());
        Ok(())
    }

    pub fn add_predicate(&mut self, attr_name: &str, p_type: &str, value: i32) -> ClResult<()> {
        let p_type = match p_type {
            "GE" => PredicateType::GE,
            "LE" => PredicateType::LE,
            "GT" => PredicateType::GT,
            "LT" => PredicateType::LT,
            p_type => {
                return Err(err_msg!("Invalid predicate type: {:?}", p_type));
            }
        };

        let predicate = Predicate {
            attr_name: attr_name.to_owned(),
            p_type,
            value,
        };

        self.value.predicates.insert(predicate);
        Ok(())
    }

    pub fn finalize(self) -> ClResult<SubProofRequest> {
        Ok(self.value)
    }
}

/// Some condition that must be satisfied.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Predicate {
    pub(crate) attr_name: String,
    pub(crate) p_type: PredicateType,
    pub(crate) value: i32,
}

impl Predicate {
    pub fn get_delta(&self, attr_value: i32) -> i32 {
        match self.p_type {
            PredicateType::GE => attr_value - self.value,
            PredicateType::GT => attr_value - self.value - 1,
            PredicateType::LE => self.value - attr_value,
            PredicateType::LT => self.value - attr_value - 1,
        }
    }

    pub fn get_delta_prime(&self) -> ClResult<BigNumber> {
        match self.p_type {
            PredicateType::GE => BigNumber::from_dec(&self.value.to_string()),
            PredicateType::GT => BigNumber::from_dec(&(self.value + 1).to_string()),
            PredicateType::LE => BigNumber::from_dec(&self.value.to_string()),
            PredicateType::LT => BigNumber::from_dec(&(self.value - 1).to_string()),
        }
    }

    pub fn is_less(&self) -> bool {
        match self.p_type {
            PredicateType::GE | PredicateType::GT => false,
            PredicateType::LE | PredicateType::LT => true,
        }
    }
}

/// Condition type
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, PartialEq, Eq, Ord, PartialOrd, Hash)]
pub enum PredicateType {
    GE,
    LE,
    GT,
    LT,
}

/// Proof is complex crypto structure created by prover over multiple credentials that allows to prove that prover:
/// 1) Knows signature over credentials issued with specific issuer keys (identified by key id)
/// 2) Credential contains attributes with specific values that prover wants to disclose
/// 3) Credential contains attributes with valid predicates that verifier wants the prover to satisfy.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug)]
pub struct Proof {
    pub proofs: Vec<SubProof>,
    pub aggregated_proof: AggregatedProof,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug)]
pub struct SubProof {
    pub(crate) primary_proof: PrimaryProof,
    pub(crate) non_revoc_proof: Option<NonRevocProof>,
}

impl SubProof {
    pub fn revealed_attrs(&self) -> ClResult<HashMap<String, String>> {
        let mut res = HashMap::new();
        for (k, v) in self.primary_proof.eq_proof.revealed_attrs.iter() {
            res.insert(k.clone(), v.to_dec()?);
        }
        Ok(res)
    }
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Eq, PartialEq)]
pub struct AggregatedProof {
    pub(crate) c_hash: BigNumber,
    pub(crate) c_list: Vec<Vec<u8>>,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, PartialEq, Eq)]
pub struct PrimaryProof {
    pub(crate) eq_proof: PrimaryEqualProof,
    #[cfg_attr(feature = "serde", serde(rename = "ge_proofs"))]
    pub(crate) ne_proofs: Vec<PrimaryPredicateInequalityProof>,
}

#[cfg_attr(feature = "serde", derive(Serialize))]
#[derive(Debug, PartialEq, Eq)]
pub struct PrimaryEqualProof {
    pub(crate) revealed_attrs: BTreeMap<String /* attr_name of revealed */, BigNumber>,
    pub(crate) a_prime: BigNumber,
    pub(crate) e: BigNumber,
    pub(crate) v: BigNumber,
    pub(crate) m: HashMap<String /* attr_name of all except revealed */, BigNumber>,
    pub(crate) m2: BigNumber,
}

#[cfg(feature = "serde")]
impl<'a> ::serde::de::Deserialize<'a> for PrimaryEqualProof {
    fn deserialize<D: ::serde::de::Deserializer<'a>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct PrimaryEqualProofV1 {
            revealed_attrs: BTreeMap<String /* attr_name of revealed */, BigNumber>,
            a_prime: BigNumber,
            e: BigNumber,
            v: BigNumber,
            m: HashMap<String /* attr_name of all except revealed */, BigNumber>,
            #[serde(default)]
            m1: BigNumber,
            m2: BigNumber,
        }

        let mut helper = PrimaryEqualProofV1::deserialize(deserializer)?;
        if helper.m1 != BigNumber::default() {
            helper.m.insert("master_secret".to_string(), helper.m1);
        }
        Ok(PrimaryEqualProof {
            revealed_attrs: helper.revealed_attrs,
            a_prime: helper.a_prime,
            e: helper.e,
            v: helper.v,
            m: helper.m,
            m2: helper.m2,
        })
    }
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, PartialEq, Eq)]
pub struct PrimaryPredicateInequalityProof {
    pub(crate) u: HashMap<String, BigNumber>,
    pub(crate) r: HashMap<String, BigNumber>,
    pub(crate) mj: BigNumber,
    pub(crate) alpha: BigNumber,
    pub(crate) t: HashMap<String, BigNumber>,
    pub(crate) predicate: Predicate,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug)]
pub struct NonRevocProof {
    pub(crate) x_list: NonRevocProofXList,
    pub(crate) c_list: NonRevocProofCList,
}

#[derive(Debug)]
pub struct InitProof {
    pub(crate) primary_init_proof: PrimaryInitProof,
    pub(crate) non_revoc_init_proof: Option<NonRevocInitProof>,
    pub(crate) credential_values: CredentialValues,
    pub(crate) sub_proof_request: SubProofRequest,
    pub(crate) credential_schema: CredentialSchema,
    pub(crate) non_credential_schema: NonCredentialSchema,
}

#[derive(Debug, Eq, PartialEq)]
pub struct PrimaryInitProof {
    pub(crate) eq_proof: PrimaryEqualInitProof,
    pub(crate) ne_proofs: Vec<PrimaryPredicateInequalityInitProof>,
}

impl PrimaryInitProof {
    pub fn as_c_list(&self) -> ClResult<Vec<Vec<u8>>> {
        let mut c_list: Vec<Vec<u8>> = self.eq_proof.as_list()?;
        for ne_proof in self.ne_proofs.iter() {
            c_list.append_vec(ne_proof.as_list()?)?;
        }
        Ok(c_list)
    }

    pub fn as_tau_list(&self) -> ClResult<Vec<Vec<u8>>> {
        let mut tau_list: Vec<Vec<u8>> = self.eq_proof.as_tau_list()?;
        for ne_proof in self.ne_proofs.iter() {
            tau_list.append_vec(ne_proof.as_tau_list()?)?;
        }
        Ok(tau_list)
    }
}

#[derive(Debug)]
pub struct NonRevocInitProof {
    pub(crate) c_list_params: NonRevocProofXList,
    pub(crate) tau_list_params: NonRevocProofXList,
    pub(crate) c_list: NonRevocProofCList,
    pub(crate) tau_list: NonRevocProofTauList,
}

impl NonRevocInitProof {
    pub fn as_c_list(&self) -> ClResult<Vec<Vec<u8>>> {
        let vec = self.c_list.as_list()?;
        Ok(vec)
    }

    pub fn as_tau_list(&self) -> ClResult<Vec<Vec<u8>>> {
        let vec = self.tau_list.as_slice()?;
        Ok(vec)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct PrimaryEqualInitProof {
    pub(crate) a_prime: BigNumber,
    pub(crate) t: BigNumber,
    pub(crate) e_tilde: BigNumber,
    pub(crate) e_prime: BigNumber,
    pub(crate) v_tilde: BigNumber,
    pub(crate) v_prime: BigNumber,
    pub(crate) m_tilde: HashMap<String, BigNumber>,
    pub(crate) m2_tilde: BigNumber,
    pub(crate) m2: BigNumber,
}

impl PrimaryEqualInitProof {
    pub fn as_list(&self) -> ClResult<Vec<Vec<u8>>> {
        Ok(vec![self.a_prime.to_bytes()?])
    }

    pub fn as_tau_list(&self) -> ClResult<Vec<Vec<u8>>> {
        Ok(vec![self.t.to_bytes()?])
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct PrimaryPredicateInequalityInitProof {
    pub(crate) c_list: Vec<BigNumber>,
    pub(crate) tau_list: Vec<BigNumber>,
    pub(crate) u: HashMap<String, BigNumber>,
    pub(crate) u_tilde: HashMap<String, BigNumber>,
    pub(crate) r: HashMap<String, BigNumber>,
    pub(crate) r_tilde: HashMap<String, BigNumber>,
    pub(crate) alpha_tilde: BigNumber,
    pub(crate) predicate: Predicate,
    pub(crate) t: HashMap<String, BigNumber>,
}

impl PrimaryPredicateInequalityInitProof {
    pub fn as_list(&self) -> ClResult<&Vec<BigNumber>> {
        Ok(&self.c_list)
    }

    pub fn as_tau_list(&self) -> ClResult<&Vec<BigNumber>> {
        Ok(&self.tau_list)
    }
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug)]
pub struct NonRevocProofXList {
    pub(crate) rho: GroupOrderElement,
    pub(crate) r: GroupOrderElement,
    pub(crate) r_prime: GroupOrderElement,
    pub(crate) r_prime_prime: GroupOrderElement,
    pub(crate) r_prime_prime_prime: GroupOrderElement,
    pub(crate) o: GroupOrderElement,
    pub(crate) o_prime: GroupOrderElement,
    pub(crate) m: GroupOrderElement,
    pub(crate) m_prime: GroupOrderElement,
    pub(crate) t: GroupOrderElement,
    pub(crate) t_prime: GroupOrderElement,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub(crate) m2: Option<GroupOrderElement>,
    pub(crate) s: GroupOrderElement,
    pub(crate) c: GroupOrderElement,
}

impl NonRevocProofXList {
    pub fn as_list(&self) -> ClResult<Vec<GroupOrderElement>> {
        let mut ret = vec![
            self.rho,
            self.o,
            self.c,
            self.o_prime,
            self.m,
            self.m_prime,
            self.t,
            self.t_prime,
            self.s,
            self.r,
            self.r_prime,
            self.r_prime_prime,
            self.r_prime_prime_prime,
        ];
        if let Some(m2) = self.m2.as_ref() {
            ret.splice(8..8, [*m2]);
        }
        Ok(ret)
    }

    pub fn from_list(seq: &[GroupOrderElement]) -> NonRevocProofXList {
        NonRevocProofXList {
            rho: seq[0],
            r: seq[9],
            r_prime: seq[10],
            r_prime_prime: seq[11],
            r_prime_prime_prime: seq[12],
            o: seq[1],
            o_prime: seq[3],
            m: seq[4],
            m_prime: seq[5],
            t: seq[6],
            t_prime: seq[7],
            m2: None,
            s: seq[8],
            c: seq[2],
        }
    }
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug)]
pub struct NonRevocProofCList {
    pub(crate) e: PointG1,
    pub(crate) d: PointG1,
    pub(crate) a: PointG1,
    pub(crate) g: PointG1,
    pub(crate) w: PointG2,
    pub(crate) s: PointG2,
    pub(crate) u: PointG2,
}

impl NonRevocProofCList {
    pub fn as_list(&self) -> ClResult<Vec<Vec<u8>>> {
        Ok(vec![
            self.e.to_bytes()?,
            self.d.to_bytes()?,
            self.a.to_bytes()?,
            self.g.to_bytes()?,
            self.w.to_bytes()?,
            self.s.to_bytes()?,
            self.u.to_bytes()?,
        ])
    }
}

#[derive(Clone, Debug)]
pub struct NonRevocProofTauList {
    pub(crate) t1: PointG1,
    pub(crate) t2: PointG1,
    pub(crate) t3: Pair,
    pub(crate) t4: Pair,
    pub(crate) t5: PointG1,
    pub(crate) t6: PointG1,
    pub(crate) t7: Pair,
    pub(crate) t8: Pair,
}

impl NonRevocProofTauList {
    pub fn as_slice(&self) -> ClResult<Vec<Vec<u8>>> {
        Ok(vec![
            self.t1.to_bytes()?,
            self.t2.to_bytes()?,
            self.t3.to_bytes()?,
            self.t4.to_bytes()?,
            self.t5.to_bytes()?,
            self.t6.to_bytes()?,
            self.t7.to_bytes()?,
            self.t8.to_bytes()?,
        ])
    }
}

/// Random BigNumber that uses `Prover` for proof generation and `Verifier` for proof verification.
pub type Nonce = BigNumber;

#[derive(Debug)]
pub struct VerifiableCredential {
    pub(crate) pub_key: CredentialPublicKey,
    pub(crate) sub_proof_request: SubProofRequest,
    pub(crate) credential_schema: CredentialSchema,
    pub(crate) non_credential_schema: NonCredentialSchema,
    pub(crate) rev_key_pub: Option<RevocationKeyPublic>,
    pub(crate) rev_reg: Option<RevocationRegistry>,
}

pub trait BytesView {
    fn to_bytes(&self) -> ClResult<Vec<u8>>;
}

impl BytesView for BigNumber {
    fn to_bytes(&self) -> ClResult<Vec<u8>> {
        self.to_bytes()
    }
}

impl BytesView for PointG1 {
    fn to_bytes(&self) -> ClResult<Vec<u8>> {
        self.to_bytes()
    }
}

impl BytesView for GroupOrderElement {
    fn to_bytes(&self) -> ClResult<Vec<u8>> {
        self.to_bytes()
    }
}

impl BytesView for Pair {
    fn to_bytes(&self) -> ClResult<Vec<u8>> {
        self.to_bytes()
    }
}

pub trait AppendByteArray {
    fn append_vec<T: BytesView>(&mut self, other: &[T]) -> ClResult<()>;
}

impl AppendByteArray for Vec<Vec<u8>> {
    fn append_vec<T: BytesView>(&mut self, other: &[T]) -> ClResult<()> {
        for el in other.iter() {
            self.push(el.to_bytes()?);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tail_accum_range() {
        let ranges = [0..=10, 10..=0, 1..=2, 1..=1];

        for range in ranges {
            let g_dash = PointG2::new().unwrap();
            let gamma = GroupOrderElement::new().unwrap();

            let mut acc1 = PointG2::new_inf().unwrap();
            let mut r = range.clone().into_inner();
            if r.0 > r.1 {
                std::mem::swap(&mut r.0, &mut r.1);
            }
            for idx in r.0..=r.1 {
                acc1 = acc1
                    .add(&Tail::new(idx, &g_dash, &gamma).unwrap().0)
                    .unwrap();
            }

            let acc2 = Tail::accum_range(&g_dash, &gamma, range.clone()).unwrap();
            assert_eq!(
                Accumulator::from(acc1),
                acc2,
                "Invalid accum for range {:?}",
                range
            );
        }
    }

    #[test]
    fn tail_accum_indexes() {
        let g_dash = PointG2::new().unwrap();
        let gamma = GroupOrderElement::new().unwrap();
        let indexes = [1, 2, 3, 5, 6];
        let index_set = BTreeSet::from_iter(indexes.iter().copied());
        let mut acc1 = PointG2::new_inf().unwrap();
        for idx in indexes {
            acc1 = acc1
                .add(&Tail::new(idx, &g_dash, &gamma).unwrap().0)
                .unwrap();
        }
        let acc2 = Tail::accum_indexes(&g_dash, &gamma, &index_set).unwrap();
        assert_eq!(Accumulator::from(acc1), acc2);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn deser_infinity_accum() {
        let reg: RevocationRegistry = serde_json::from_str(r#"{"accum":"1 0000000000000000000000000000000000000000000000000000000000000000 1 0000000000000000000000000000000000000000000000000000000000000000 1 0000000000000000000000000000000000000000000000000000000000000000 1 0000000000000000000000000000000000000000000000000000000000000000 1 0000000000000000000000000000000000000000000000000000000000000000 1 0000000000000000000000000000000000000000000000000000000000000000"}"#).unwrap();
        assert!(reg.accum.is_inf().unwrap());
    }
}
