/*
    This file contains duplicate definitions for types requiring more optimal bytes serialization.
    By default crypto primitives such BugNumber's, Points, etc. are represented as string during the serde serialization.
    But in case of using message pack or cbor these crypto primitives needs to be represented as bytes.
    Because of the issue: https://github.com/serde-rs/serde/issues/2656 we cannot change serialization way in runtime on the application level.
    Instead we provide duplicate types which application can use for more optimal serialization only.
    All library API methods work with regular type definitions using BigNum, Points, etc.
*/

// This module can be dropped if we figure out how to write serde serialization based on the parameter
//  instead of using feature flag as demonstrated below.
//
//  Feature based condition is not applicable in the case if application need to use serialization in in both forms.
//
//  Why it is needed:
//      JSON string serialization - BigNumber must be encoded as decimal string for more compact representation
//      Message Pack and CBOR serialization - BigNumber must be encoded as bytes for more compact representation
/*
#[cfg(feature = "serde")]
impl Serialize for BigNumber {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if cfg!(feature = "type_extensions") {
            serializer.serialize_newtype_struct(
                "BigNumber",
                &self.to_bytes().map_err(serde::ser::Error::custom)?,
            )
        } else {
            serializer.serialize_newtype_struct(
                "BigNumber",
                &self.to_dec().map_err(serde::ser::Error::custom)?,
            )
        }
    }
}
*/
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{types::*, Error};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

#[derive(Serialize, Deserialize, Debug)]
pub struct CredentialPublicKeyBytesProxy {
    p_key: CredentialPrimaryPublicKeyBytesProxy,
    r_key: Option<CredentialRevocationPublicKeyBytesProxy>,
}

impl TryFrom<CredentialPublicKey> for CredentialPublicKeyBytesProxy {
    type Error = Error;

    fn try_from(value: CredentialPublicKey) -> Result<Self, Self::Error> {
        Ok(CredentialPublicKeyBytesProxy {
            p_key: value.p_key.try_into()?,
            r_key: match value.r_key {
                Some(r_key) => Some(r_key.try_into()?),
                None => None,
            },
        })
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CredentialPrimaryPublicKeyBytesProxy {
    n: Vec<u8>,
    s: Vec<u8>,
    r: HashMap<String, Vec<u8>>,
    rctxt: Vec<u8>,
    z: Vec<u8>,
}

impl TryFrom<CredentialPrimaryPublicKey> for CredentialPrimaryPublicKeyBytesProxy {
    type Error = Error;

    fn try_from(value: CredentialPrimaryPublicKey) -> Result<Self, Self::Error> {
        let mut r: HashMap<String, Vec<u8>> = HashMap::new();
        for (key, value) in value.r.into_iter() {
            r.insert(key, value.to_bytes()?);
        }

        Ok(CredentialPrimaryPublicKeyBytesProxy {
            n: value.n.to_bytes()?,
            s: value.s.to_bytes()?,
            r,
            rctxt: value.rctxt.to_bytes()?,
            z: value.z.to_bytes()?,
        })
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CredentialPrimaryPrivateKeyBytesProxy {
    p: Vec<u8>,
    q: Vec<u8>,
}

impl TryFrom<CredentialPrimaryPrivateKey> for CredentialPrimaryPrivateKeyBytesProxy {
    type Error = Error;

    fn try_from(value: CredentialPrimaryPrivateKey) -> Result<Self, Self::Error> {
        Ok(CredentialPrimaryPrivateKeyBytesProxy {
            p: value.p.to_bytes()?,
            q: value.q.to_bytes()?,
        })
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CredentialRevocationPublicKeyBytesProxy {
    g: Vec<u8>,
    g_dash: Vec<u8>,
    h: Vec<u8>,
    h0: Vec<u8>,
    h1: Vec<u8>,
    h2: Vec<u8>,
    htilde: Vec<u8>,
    h_cap: Vec<u8>,
    u: Vec<u8>,
    pk: Vec<u8>,
    y: Vec<u8>,
}

impl TryFrom<CredentialRevocationPublicKey> for CredentialRevocationPublicKeyBytesProxy {
    type Error = Error;

    fn try_from(value: CredentialRevocationPublicKey) -> Result<Self, Self::Error> {
        Ok(CredentialRevocationPublicKeyBytesProxy {
            g: value.g.to_bytes()?,
            g_dash: value.g_dash.to_bytes()?,
            h: value.h.to_bytes()?,
            h0: value.h0.to_bytes()?,
            h1: value.h1.to_bytes()?,
            h2: value.h2.to_bytes()?,
            htilde: value.htilde.to_bytes()?,
            h_cap: value.h_cap.to_bytes()?,
            u: value.u.to_bytes()?,
            pk: value.pk.to_bytes()?,
            y: value.y.to_bytes()?,
        })
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CredentialRevocationPrivateKeyBytesProxy {
    x: Vec<u8>,
    sk: Vec<u8>,
}

impl TryFrom<CredentialRevocationPrivateKey> for CredentialRevocationPrivateKeyBytesProxy {
    type Error = Error;

    fn try_from(value: CredentialRevocationPrivateKey) -> Result<Self, Self::Error> {
        Ok(CredentialRevocationPrivateKeyBytesProxy {
            x: value.x.to_bytes()?,
            sk: value.sk.to_bytes()?,
        })
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CredentialKeyCorrectnessProofBytesProxy {
    c: Vec<u8>,
    xz_cap: Vec<u8>,
    xr_cap: Vec<(String, Vec<u8>)>,
}

impl TryFrom<CredentialKeyCorrectnessProof> for CredentialKeyCorrectnessProofBytesProxy {
    type Error = Error;

    fn try_from(value: CredentialKeyCorrectnessProof) -> Result<Self, Self::Error> {
        let mut xr_cap: Vec<(String, Vec<u8>)> = Vec::with_capacity(value.xr_cap.len());
        for (key, value) in value.xr_cap.into_iter() {
            xr_cap.push((key, value.to_bytes()?));
        }

        Ok(CredentialKeyCorrectnessProofBytesProxy {
            c: value.c.to_bytes()?,
            xz_cap: value.xz_cap.to_bytes()?,
            xr_cap,
        })
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CredentialSignatureBytesProxy {
    p_credential: PrimaryCredentialSignatureBytesProxy,
    r_credential: Option<NonRevocationCredentialSignatureBytesProxy>,
}

impl TryFrom<CredentialSignature> for CredentialSignatureBytesProxy {
    type Error = Error;

    fn try_from(value: CredentialSignature) -> Result<Self, Self::Error> {
        Ok(CredentialSignatureBytesProxy {
            p_credential: value.p_credential.try_into()?,
            r_credential: match value.r_credential {
                Some(r_credential) => Some(r_credential.try_into()?),
                None => None,
            },
        })
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PrimaryCredentialSignatureBytesProxy {
    m_2: Vec<u8>,
    a: Vec<u8>,
    e: Vec<u8>,
    v: Vec<u8>,
}

impl TryFrom<PrimaryCredentialSignature> for PrimaryCredentialSignatureBytesProxy {
    type Error = Error;

    fn try_from(value: PrimaryCredentialSignature) -> Result<Self, Self::Error> {
        Ok(PrimaryCredentialSignatureBytesProxy {
            m_2: value.m_2.to_bytes()?,
            a: value.a.to_bytes()?,
            e: value.e.to_bytes()?,
            v: value.v.to_bytes()?,
        })
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct NonRevocationCredentialSignatureBytesProxy {
    sigma: Vec<u8>,
    c: Vec<u8>,
    vr_prime_prime: Vec<u8>,
    witness_signature: WitnessSignatureBytesProxy,
    g_i: Vec<u8>,
    i: u32,
    m2: Vec<u8>,
}

impl TryFrom<NonRevocationCredentialSignature> for NonRevocationCredentialSignatureBytesProxy {
    type Error = Error;

    fn try_from(value: NonRevocationCredentialSignature) -> Result<Self, Self::Error> {
        Ok(NonRevocationCredentialSignatureBytesProxy {
            sigma: value.sigma.to_bytes()?,
            c: value.c.to_bytes()?,
            vr_prime_prime: value.vr_prime_prime.to_bytes()?,
            witness_signature: value.witness_signature.try_into()?,
            g_i: value.g_i.to_bytes()?,
            i: value.i.clone(),
            m2: value.m2.to_bytes()?,
        })
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct WitnessSignatureBytesProxy {
    sigma_i: Vec<u8>,
    u_i: Vec<u8>,
    g_i: Vec<u8>,
}

impl TryFrom<WitnessSignature> for WitnessSignatureBytesProxy {
    type Error = Error;

    fn try_from(value: WitnessSignature) -> Result<Self, Self::Error> {
        Ok(WitnessSignatureBytesProxy {
            sigma_i: value.sigma_i.to_bytes()?,
            u_i: value.u_i.to_bytes()?,
            g_i: value.g_i.to_bytes()?,
        })
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SignatureCorrectnessProofBytesProxy {
    se: Vec<u8>,
    c: Vec<u8>,
}

impl TryFrom<SignatureCorrectnessProof> for SignatureCorrectnessProofBytesProxy {
    type Error = Error;

    fn try_from(value: SignatureCorrectnessProof) -> Result<Self, Self::Error> {
        Ok(SignatureCorrectnessProofBytesProxy {
            se: value.se.to_bytes()?,
            c: value.c.to_bytes()?,
        })
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RevocationRegistryBytesProxy {
    accum: AccumulatorBytesProxy,
}

impl TryFrom<RevocationRegistry> for RevocationRegistryBytesProxy {
    type Error = Error;

    fn try_from(value: RevocationRegistry) -> Result<Self, Self::Error> {
        Ok(RevocationRegistryBytesProxy {
            accum: value.accum.try_into()?,
        })
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RevocationRegistryDeltaBytesProxy {
    prev_accum: Option<AccumulatorBytesProxy>,
    accum: AccumulatorBytesProxy,
    issued: HashSet<u32>,
    revoked: HashSet<u32>,
}

impl TryFrom<RevocationRegistryDelta> for RevocationRegistryDeltaBytesProxy {
    type Error = Error;

    fn try_from(value: RevocationRegistryDelta) -> Result<Self, Self::Error> {
        Ok(RevocationRegistryDeltaBytesProxy {
            prev_accum: match value.prev_accum {
                Some(prev_accum) => Some(prev_accum.try_into()?),
                None => None,
            },
            accum: value.accum.try_into()?,
            issued: value.issued,
            revoked: value.revoked,
        })
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RevocationKeyPublicBytesProxy {
    z: Vec<u8>,
}

impl TryFrom<RevocationKeyPublic> for RevocationKeyPublicBytesProxy {
    type Error = Error;

    fn try_from(value: RevocationKeyPublic) -> Result<Self, Self::Error> {
        Ok(RevocationKeyPublicBytesProxy {
            z: value.z.to_bytes()?,
        })
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RevocationKeyPrivateBytesProxy {
    gamma: Vec<u8>,
}

impl TryFrom<RevocationKeyPrivate> for RevocationKeyPrivateBytesProxy {
    type Error = Error;

    fn try_from(value: RevocationKeyPrivate) -> Result<Self, Self::Error> {
        Ok(RevocationKeyPrivateBytesProxy {
            gamma: value.gamma.to_bytes()?,
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(transparent)]
#[derive(Debug)]
pub struct TailBytesProxy(Vec<u8>);

impl TryFrom<Tail> for TailBytesProxy {
    type Error = Error;

    fn try_from(value: Tail) -> Result<Self, Self::Error> {
        Ok(TailBytesProxy(value.to_bytes()?))
    }
}

#[derive(Serialize, Deserialize)]
#[serde(transparent)]
#[derive(Debug)]
pub struct AccumulatorBytesProxy(Vec<u8>);

impl TryFrom<Accumulator> for AccumulatorBytesProxy {
    type Error = Error;

    fn try_from(value: Accumulator) -> Result<Self, Self::Error> {
        Ok(AccumulatorBytesProxy(value.to_bytes()?))
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct WitnessBytesProxy {
    omega: Vec<u8>,
}

impl TryFrom<Witness> for WitnessBytesProxy {
    type Error = Error;

    fn try_from(value: Witness) -> Result<Self, Self::Error> {
        Ok(WitnessBytesProxy {
            omega: value.omega.0.to_bytes()?,
        })
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ProofBytesProxy {
    proofs: Vec<SubProofBytesProxy>,
    aggregated_proof: AggregatedProofBytesProxy,
}

impl TryFrom<Proof> for ProofBytesProxy {
    type Error = Error;

    fn try_from(value: Proof) -> Result<Self, Self::Error> {
        Ok(ProofBytesProxy {
            proofs: value
                .proofs
                .into_iter()
                .map(|proof| proof.try_into())
                .collect::<Result<Vec<SubProofBytesProxy>, Self::Error>>()?,
            aggregated_proof: value.aggregated_proof.try_into()?,
        })
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SubProofBytesProxy {
    primary_proof: PrimaryProofBytesProxy,
    non_revoc_proof: Option<NonRevocProofBytesProxy>,
}

impl TryFrom<SubProof> for SubProofBytesProxy {
    type Error = Error;

    fn try_from(value: SubProof) -> Result<Self, Self::Error> {
        Ok(SubProofBytesProxy {
            primary_proof: value.primary_proof.try_into()?,
            non_revoc_proof: match value.non_revoc_proof {
                Some(non_revoc_proof) => Some(non_revoc_proof.try_into()?),
                None => None,
            },
        })
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PrimaryProofBytesProxy {
    eq_proof: PrimaryEqualProofBytesProxy,
    #[cfg_attr(feature = "serde", serde(rename = "ge_proofs"))]
    ne_proofs: Vec<PrimaryPredicateInequalityProofBytesProxy>,
}

impl TryFrom<PrimaryProof> for PrimaryProofBytesProxy {
    type Error = Error;

    fn try_from(value: PrimaryProof) -> Result<Self, Self::Error> {
        Ok(PrimaryProofBytesProxy {
            eq_proof: value.eq_proof.try_into()?,
            ne_proofs: value
                .ne_proofs
                .into_iter()
                .map(PrimaryPredicateInequalityProofBytesProxy::try_from)
                .collect::<Result<Vec<PrimaryPredicateInequalityProofBytesProxy>, Error>>()?,
        })
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PrimaryEqualProofBytesProxy {
    revealed_attrs: BTreeMap<String, Vec<u8>>,
    a_prime: Vec<u8>,
    e: Vec<u8>,
    v: Vec<u8>,
    m: HashMap<String, Vec<u8>>,
    m2: Vec<u8>,
}

impl TryFrom<PrimaryEqualProof> for PrimaryEqualProofBytesProxy {
    type Error = Error;

    fn try_from(value: PrimaryEqualProof) -> Result<Self, Self::Error> {
        let mut revealed_attrs: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        for (key, value) in value.revealed_attrs.into_iter() {
            revealed_attrs.insert(key, value.to_bytes()?);
        }

        let mut m: HashMap<String, Vec<u8>> = HashMap::new();
        for (key, value) in value.m.into_iter() {
            m.insert(key, value.to_bytes()?);
        }

        Ok(PrimaryEqualProofBytesProxy {
            revealed_attrs,
            a_prime: value.a_prime.to_bytes()?,
            e: value.e.to_bytes()?,
            v: value.v.to_bytes()?,
            m,
            m2: value.m2.to_bytes()?,
        })
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PrimaryPredicateInequalityProofBytesProxy {
    u: HashMap<String, Vec<u8>>,
    r: HashMap<String, Vec<u8>>,
    mj: Vec<u8>,
    alpha: Vec<u8>,
    t: HashMap<String, Vec<u8>>,
    predicate: Predicate,
}

impl TryFrom<PrimaryPredicateInequalityProof> for PrimaryPredicateInequalityProofBytesProxy {
    type Error = Error;

    fn try_from(value: PrimaryPredicateInequalityProof) -> Result<Self, Self::Error> {
        let mut u: HashMap<String, Vec<u8>> = HashMap::new();
        for (key, value) in value.u.into_iter() {
            u.insert(key, value.to_bytes()?);
        }

        let mut r: HashMap<String, Vec<u8>> = HashMap::new();
        for (key, value) in value.r.into_iter() {
            r.insert(key, value.to_bytes()?);
        }

        let mut t: HashMap<String, Vec<u8>> = HashMap::new();
        for (key, value) in value.t.into_iter() {
            t.insert(key, value.to_bytes()?);
        }

        Ok(PrimaryPredicateInequalityProofBytesProxy {
            u,
            r,
            mj: value.mj.to_bytes()?,
            alpha: value.alpha.to_bytes()?,
            t,
            predicate: value.predicate,
        })
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct NonRevocProofBytesProxy {
    x_list: NonRevocProofXListBytesProxy,
    c_list: NonRevocProofCListBytesProxy,
}

impl TryFrom<NonRevocProof> for NonRevocProofBytesProxy {
    type Error = Error;

    fn try_from(value: NonRevocProof) -> Result<Self, Self::Error> {
        Ok(NonRevocProofBytesProxy {
            x_list: value.x_list.try_into()?,
            c_list: value.c_list.try_into()?,
        })
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct NonRevocProofCListBytesProxy {
    e: Vec<u8>,
    d: Vec<u8>,
    a: Vec<u8>,
    g: Vec<u8>,
    w: Vec<u8>,
    s: Vec<u8>,
    u: Vec<u8>,
}

impl TryFrom<NonRevocProofCList> for NonRevocProofCListBytesProxy {
    type Error = Error;

    fn try_from(value: NonRevocProofCList) -> Result<Self, Self::Error> {
        Ok(NonRevocProofCListBytesProxy {
            e: value.e.to_bytes()?,
            d: value.d.to_bytes()?,
            a: value.a.to_bytes()?,
            g: value.g.to_bytes()?,
            w: value.w.to_bytes()?,
            s: value.s.to_bytes()?,
            u: value.u.to_bytes()?,
        })
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct NonRevocProofTauListBytesProxy {
    t1: Vec<u8>,
    t2: Vec<u8>,
    t3: Vec<u8>,
    t4: Vec<u8>,
    t5: Vec<u8>,
    t6: Vec<u8>,
    t7: Vec<u8>,
    t8: Vec<u8>,
}

impl TryFrom<NonRevocProofTauList> for NonRevocProofTauListBytesProxy {
    type Error = Error;

    fn try_from(value: NonRevocProofTauList) -> Result<Self, Self::Error> {
        Ok(NonRevocProofTauListBytesProxy {
            t1: value.t1.to_bytes()?,
            t2: value.t2.to_bytes()?,
            t3: value.t3.to_bytes()?,
            t4: value.t4.to_bytes()?,
            t5: value.t5.to_bytes()?,
            t6: value.t6.to_bytes()?,
            t7: value.t7.to_bytes()?,
            t8: value.t8.to_bytes()?,
        })
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct NonRevocProofXListBytesProxy {
    rho: Vec<u8>,
    r: Vec<u8>,
    r_prime: Vec<u8>,
    r_prime_prime: Vec<u8>,
    r_prime_prime_prime: Vec<u8>,
    o: Vec<u8>,
    o_prime: Vec<u8>,
    m: Vec<u8>,
    m_prime: Vec<u8>,
    t: Vec<u8>,
    t_prime: Vec<u8>,
    m2: Option<Vec<u8>>,
    s: Vec<u8>,
    c: Vec<u8>,
}

impl TryFrom<NonRevocProofXList> for NonRevocProofXListBytesProxy {
    type Error = Error;

    fn try_from(value: NonRevocProofXList) -> Result<Self, Self::Error> {
        Ok(NonRevocProofXListBytesProxy {
            rho: value.rho.to_bytes()?,
            r: value.r.to_bytes()?,
            r_prime: value.r_prime.to_bytes()?,
            r_prime_prime: value.r_prime_prime.to_bytes()?,
            r_prime_prime_prime: value.r_prime_prime_prime.to_bytes()?,
            o: value.o.to_bytes()?,
            o_prime: value.o_prime.to_bytes()?,
            m: value.m.to_bytes()?,
            m_prime: value.m_prime.to_bytes()?,
            t: value.t.to_bytes()?,
            t_prime: value.t_prime.to_bytes()?,
            m2: match value.m2 {
                Some(v2) => Some(v2.to_bytes()?),
                None => None,
            },
            s: value.s.to_bytes()?,
            c: value.c.to_bytes()?,
        })
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AggregatedProofBytesProxy {
    c_hash: Vec<u8>,
    c_list: Vec<Vec<u8>>,
}

impl TryFrom<AggregatedProof> for AggregatedProofBytesProxy {
    type Error = Error;

    fn try_from(value: AggregatedProof) -> Result<Self, Self::Error> {
        Ok(AggregatedProofBytesProxy {
            c_hash: value.c_hash.to_bytes()?,
            c_list: value.c_list,
        })
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LinkSecretBytesProxy {
    ms: Vec<u8>,
}

impl TryFrom<LinkSecret> for LinkSecretBytesProxy {
    type Error = Error;

    fn try_from(value: LinkSecret) -> Result<Self, Self::Error> {
        Ok(LinkSecretBytesProxy {
            ms: value.ms.to_bytes()?,
        })
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct BlindedCredentialSecretsBytesProxy {
    u: Vec<u8>,
    ur: Option<Vec<u8>>,
    hidden_attributes: BTreeSet<String>,
    committed_attributes: BTreeMap<String, Vec<u8>>,
}

impl TryFrom<BlindedCredentialSecrets> for BlindedCredentialSecretsBytesProxy {
    type Error = Error;

    fn try_from(value: BlindedCredentialSecrets) -> Result<Self, Self::Error> {
        let mut committed_attributes: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        for (key, value) in value.committed_attributes.into_iter() {
            committed_attributes.insert(key, value.to_bytes()?);
        }

        Ok(BlindedCredentialSecretsBytesProxy {
            u: value.u.to_bytes()?,
            ur: match value.ur {
                Some(ur) => Some(ur.to_bytes()?),
                None => None,
            },
            hidden_attributes: value.hidden_attributes,
            committed_attributes,
        })
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CredentialSecretsBlindingFactorsBytesProxy {
    v_prime: Vec<u8>,
    vr_prime: Option<Vec<u8>>,
}

impl TryFrom<CredentialSecretsBlindingFactors> for CredentialSecretsBlindingFactorsBytesProxy {
    type Error = Error;

    fn try_from(value: CredentialSecretsBlindingFactors) -> Result<Self, Self::Error> {
        Ok(CredentialSecretsBlindingFactorsBytesProxy {
            v_prime: value.v_prime.to_bytes()?,
            vr_prime: match value.vr_prime {
                Some(vr_prime) => Some(vr_prime.to_bytes()?),
                None => None,
            },
        })
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PrimaryBlindedCredentialSecretsFactorsBytesProxy {
    u: Vec<u8>,
    v_prime: Vec<u8>,
    hidden_attributes: BTreeSet<String>,
    committed_attributes: BTreeMap<String, Vec<u8>>,
}

impl TryFrom<PrimaryBlindedCredentialSecretsFactors>
    for PrimaryBlindedCredentialSecretsFactorsBytesProxy
{
    type Error = Error;

    fn try_from(value: PrimaryBlindedCredentialSecretsFactors) -> Result<Self, Self::Error> {
        let mut committed_attributes: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        for (key, value) in value.committed_attributes.into_iter() {
            committed_attributes.insert(key, value.to_bytes()?);
        }

        Ok(PrimaryBlindedCredentialSecretsFactorsBytesProxy {
            u: value.u.to_bytes()?,
            v_prime: value.v_prime.to_bytes()?,
            hidden_attributes: value.hidden_attributes,
            committed_attributes,
        })
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RevocationBlindedCredentialSecretsFactorsBytesProxy {
    ur: Vec<u8>,
    vr_prime: Vec<u8>,
}

impl TryFrom<RevocationBlindedCredentialSecretsFactors>
    for RevocationBlindedCredentialSecretsFactorsBytesProxy
{
    type Error = Error;

    fn try_from(value: RevocationBlindedCredentialSecretsFactors) -> Result<Self, Self::Error> {
        Ok(RevocationBlindedCredentialSecretsFactorsBytesProxy {
            ur: value.ur.to_bytes()?,
            vr_prime: value.vr_prime.to_bytes()?,
        })
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct BlindedCredentialSecretsCorrectnessProofBytesProxy {
    c: Vec<u8>,
    v_dash_cap: Vec<u8>,
    m_caps: BTreeMap<String, Vec<u8>>,
    r_caps: BTreeMap<String, Vec<u8>>,
}

impl TryFrom<BlindedCredentialSecretsCorrectnessProof>
    for BlindedCredentialSecretsCorrectnessProofBytesProxy
{
    type Error = Error;

    fn try_from(value: BlindedCredentialSecretsCorrectnessProof) -> Result<Self, Self::Error> {
        let mut m_caps: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        for (key, value) in value.m_caps.into_iter() {
            m_caps.insert(key, value.to_bytes()?);
        }

        let mut r_caps: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        for (key, value) in value.r_caps.into_iter() {
            r_caps.insert(key, value.to_bytes()?);
        }

        Ok(BlindedCredentialSecretsCorrectnessProofBytesProxy {
            c: value.c.to_bytes()?,
            v_dash_cap: value.v_dash_cap.to_bytes()?,
            m_caps,
            r_caps,
        })
    }
}
