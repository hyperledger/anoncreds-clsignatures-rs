use amcl::bn254::big::BIG;
use amcl::bn254::ecp::ECP;
use amcl::bn254::ecp2::ECP2;
use amcl::bn254::fp::FP;
use amcl::bn254::fp12::FP12;
use amcl::bn254::fp2::FP2;
use amcl::bn254::pair::{ate, ate2, fexp, g1mul, g2mul, gtpow};
use amcl::bn254::rom::{CURVE_ORDER, MODBYTES};
use amcl::rand::RAND;

use std::fmt::{self, Debug, Formatter};

#[cfg(feature = "serde")]
use serde::{de::Visitor, Deserialize, Deserializer, Serialize, Serializer};

use rand::prelude::*;

#[cfg(test)]
use std::cell::RefCell;

use crate::bn::BigNumber;
use crate::error::Result as ClResult;

const ORDER: BIG = BIG { w: CURVE_ORDER };

#[cfg(test)]
thread_local! {
  pub static PAIR_USE_MOCKS: RefCell<bool> = RefCell::new(false);
}

#[cfg(test)]
pub struct PairMocksHelper {}

#[cfg(test)]
impl PairMocksHelper {
    #[allow(unused)]
    pub fn inject() {
        PAIR_USE_MOCKS.with(|use_mocks| {
            *use_mocks.borrow_mut() = true;
        });
    }

    pub fn is_injected() -> bool {
        PAIR_USE_MOCKS.with(|use_mocks| {
            return *use_mocks.borrow();
        })
    }
}

#[cfg(not(test))]
fn random_mod_order() -> ClResult<BIG> {
    _random_mod_order()
}

#[cfg(test)]
fn random_mod_order() -> ClResult<BIG> {
    if PairMocksHelper::is_injected() {
        Ok(BIG::from_hex(
            "22EB5716FB01F2122DE924466542B923D8C96F16C9B5FE2C00B7D7DC1499EA50".to_string(),
        ))
    } else {
        _random_mod_order()
    }
}

fn _random_mod_order() -> ClResult<BIG> {
    const ENTROPY: usize = 128;
    let mut seed = [0; ENTROPY];
    let mut rng = rand::thread_rng();
    rng.fill_bytes(seed.as_mut_slice());
    let mut rng = RAND::new();
    // AMCL recommends to initialise from at least 128 bytes, check doc for `RAND.seed`
    rng.seed(ENTROPY, &seed);
    Ok(BIG::randomnum(&ORDER, &mut rng))
}

#[derive(Copy, Clone, PartialEq)]
pub struct PointG1 {
    point: ECP,
}

impl PointG1 {
    // This should be MODBYTES * 2 + 1, but is maintained for compatibility
    pub const BYTES_REPR_SIZE: usize = MODBYTES * 4;

    /// Creates new random PointG1
    pub fn new() -> ClResult<Self> {
        Self::new_generator()?.mul(&GroupOrderElement::new()?)
    }

    /// Creates new infinity PointG1
    pub fn new_inf() -> ClResult<Self> {
        let mut r = ECP::new();
        r.inf();
        Ok(PointG1 { point: r })
    }

    /// Create the generator point
    pub fn new_generator() -> ClResult<Self> {
        Ok(PointG1 {
            point: ECP::generator(),
        })
    }

    /// Checks infinity
    pub fn is_inf(&self) -> ClResult<bool> {
        Ok(self.point.is_infinity())
    }

    /// PointG1 * PointG1
    pub fn add(&self, q: &PointG1) -> ClResult<Self> {
        let mut r = self.point;
        let point = q.point;
        r.add(&point);
        Ok(PointG1 { point: r })
    }

    /// PointG1 / PointG1
    pub fn sub(&self, q: &PointG1) -> ClResult<Self> {
        let mut r = self.point;
        let point = q.point;
        r.sub(&point);
        Ok(PointG1 { point: r })
    }

    /// 1 / PointG1
    pub fn neg(&self) -> ClResult<Self> {
        let mut r = self.point;
        r.neg();
        Ok(PointG1 { point: r })
    }

    /// PointG1 ^ GroupOrderElement
    pub fn mul(&self, e: &GroupOrderElement) -> ClResult<Self> {
        let r = self.point;
        let mut bn = e.bn;
        Ok(PointG1 {
            point: g1mul(&r, &mut bn),
        })
    }

    /// Encode to hexadecimal format
    pub fn to_string(&self) -> ClResult<String> {
        Ok(self.point.to_hex())
    }

    /// Decode from hexadecimal format
    pub fn from_string(val: &str) -> ClResult<Self> {
        let res = Self::from_string_inf(val)?;
        if res.is_inf()? {
            Err(err_msg!("Invalid point: infinity"))
        } else {
            Ok(res)
        }
    }

    /// Decode from hexadecimal format, allowing for the infinity point
    pub fn from_string_inf(val: &str) -> ClResult<Self> {
        pre_validate_point(val, 3)?;
        let point = ECP::from_hex(val.to_string());
        if is_valid_ecp(&point) {
            Ok(PointG1 { point })
        } else {
            Err(err_msg!("Invalid PointG1"))
        }
    }

    /// Encode to binary format (big-endian)
    pub fn to_bytes(&self) -> ClResult<Vec<u8>> {
        let mut vec = vec![0u8; Self::BYTES_REPR_SIZE];
        self.point.tobytes(&mut vec, false);
        Ok(vec)
    }

    /// Decode from binary format (big-endian)
    #[allow(unused)]
    pub fn from_bytes(b: &[u8]) -> ClResult<Self> {
        if b.len() != Self::BYTES_REPR_SIZE {
            Err(err_msg!("Invalid byte length for PointG1"))
        } else {
            Ok(PointG1 {
                point: ECP::frombytes(b),
            })
        }
    }

    #[allow(unused)]
    pub fn from_hash(hash: &[u8]) -> ClResult<Self> {
        let mut el = GroupOrderElement::from_bytes(hash)?;
        let mut point = ECP::new_big(&el.bn);

        while point.is_infinity() {
            el.bn.inc(1);
            point = ECP::new_big(&el.bn);
        }

        Ok(PointG1 { point })
    }
}

impl Debug for PointG1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "PointG1 {{ point: {} }}", self.point.to_hex())
    }
}

#[cfg(feature = "serde")]
impl Serialize for PointG1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_newtype_struct(
            "PointG1",
            &self.to_string().map_err(serde::ser::Error::custom)?,
        )
    }
}

#[cfg(feature = "serde")]
impl<'a> Deserialize<'a> for PointG1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'a>,
    {
        deserializer.deserialize_str(StrVisitor("expected PointG1", Self::from_string))
    }
}

#[derive(Copy, Clone, PartialEq)]
pub struct PointG2 {
    point: ECP2,
}

impl PointG2 {
    pub const BYTES_REPR_SIZE: usize = MODBYTES * 4;

    /// Creates new random PointG2
    pub fn new() -> ClResult<Self> {
        Self::new_generator()?.mul(&GroupOrderElement::new()?)
    }

    /// Creates new infinity PointG2
    pub fn new_inf() -> ClResult<Self> {
        let mut point = ECP2::new();
        point.inf();
        Ok(PointG2 { point })
    }

    /// Create the generator point
    pub fn new_generator() -> ClResult<PointG2> {
        Ok(PointG2 {
            point: ECP2::generator(),
        })
    }

    /// Checks infinity
    pub fn is_inf(&self) -> ClResult<bool> {
        Ok(self.point.is_infinity())
    }

    /// PointG2 * PointG2
    pub fn add(&self, q: &PointG2) -> ClResult<PointG2> {
        let mut r = self.point;
        let point = q.point;
        r.add(&point);

        Ok(PointG2 { point: r })
    }

    /// PointG2 / PointG2
    pub fn sub(&self, q: &PointG2) -> ClResult<PointG2> {
        let mut r = self.point;
        let point = q.point;
        r.sub(&point);

        Ok(PointG2 { point: r })
    }

    pub fn neg(&self) -> ClResult<PointG2> {
        let mut r = self.point;
        r.neg();
        Ok(PointG2 { point: r })
    }

    /// PointG2 ^ GroupOrderElement
    pub fn mul(&self, e: &GroupOrderElement) -> ClResult<PointG2> {
        let r = self.point;
        let bn = e.bn;
        Ok(PointG2 {
            point: g2mul(&r, &bn),
        })
    }

    /// Encode to hexadecimal format
    pub fn to_string(&self) -> ClResult<String> {
        Ok(self.point.to_hex())
    }

    /// Decode from hexadecimal format
    pub fn from_string(val: &str) -> ClResult<Self> {
        let res = Self::from_string_inf(val)?;
        if res.is_inf()? {
            Err(err_msg!("Invalid point: infinity"))
        } else {
            Ok(res)
        }
    }

    /// Decode from hexadecimal format, allowing for the infinity point
    pub fn from_string_inf(val: &str) -> ClResult<PointG2> {
        pre_validate_point(val, 6)?;
        let point = ECP2::from_hex(val.to_string());
        if is_valid_ecp2(&point) {
            Ok(PointG2 { point })
        } else {
            Err(err_msg!("Invalid PointG2"))
        }
    }

    /// Encode to binary format (big-endian)
    pub fn to_bytes(&self) -> ClResult<Vec<u8>> {
        let mut vec = vec![0u8; Self::BYTES_REPR_SIZE];
        self.point.tobytes(&mut vec);
        Ok(vec)
    }

    /// Decode from binary format (big-endian)
    pub fn from_bytes(b: &[u8]) -> ClResult<PointG2> {
        if b.len() != Self::BYTES_REPR_SIZE {
            Err(err_msg!("Invalid byte length for PointG2"))
        } else {
            Ok(PointG2 {
                point: ECP2::frombytes(b),
            })
        }
    }
}

impl Debug for PointG2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "PointG2 {{ point: {} }}", self.point.to_hex())
    }
}

#[cfg(feature = "serde")]
impl Serialize for PointG2 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_newtype_struct(
            "PointG2",
            &self.to_string().map_err(serde::ser::Error::custom)?,
        )
    }
}

#[cfg(feature = "serde")]
impl<'a> Deserialize<'a> for PointG2 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'a>,
    {
        deserializer.deserialize_str(StrVisitor("expected PointG2", Self::from_string))
    }
}

/// A wrapper type to allow deserialization of the infinity point
#[cfg_attr(feature = "serde", derive(Serialize))]
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct PointG2Inf(pub PointG2);

impl PointG2Inf {
    pub const BYTES_REPR_SIZE: usize = PointG2::BYTES_REPR_SIZE;

    /// Creates new infinity PointG2Inf
    pub fn new_inf() -> ClResult<Self> {
        Ok(Self(PointG2::new_inf()?))
    }

    /// Checks infinity
    pub fn is_inf(&self) -> ClResult<bool> {
        self.0.is_inf()
    }

    /// Encode to hexadecimal format
    pub fn to_string(&self) -> ClResult<String> {
        self.0.to_string()
    }

    /// Decode from hexadecimal format
    pub fn from_string(val: &str) -> ClResult<Self> {
        Ok(Self(PointG2::from_string_inf(val)?))
    }
}

impl From<PointG2> for PointG2Inf {
    fn from(value: PointG2) -> Self {
        Self(value)
    }
}

impl From<PointG2Inf> for PointG2 {
    fn from(value: PointG2Inf) -> Self {
        value.0
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for PointG2Inf {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(Self(deserializer.deserialize_str(StrVisitor(
            "expected PointG2",
            PointG2::from_string_inf,
        ))?))
    }
}

#[derive(Copy, Clone, PartialEq)]
pub struct GroupOrderElement {
    bn: BIG,
}

impl GroupOrderElement {
    pub const BYTES_REPR_SIZE: usize = MODBYTES;

    pub fn new() -> ClResult<GroupOrderElement> {
        // returns random element in 0, ..., GroupOrder-1
        Ok(GroupOrderElement {
            bn: random_mod_order()?,
        })
    }

    pub fn new_u32(val: u32) -> ClResult<GroupOrderElement> {
        Ok(GroupOrderElement {
            bn: BIG::new_int(val as isize),
        })
    }

    pub fn zero() -> ClResult<GroupOrderElement> {
        Ok(GroupOrderElement { bn: BIG::new() })
    }

    pub fn order() -> ClResult<BigNumber> {
        let mut buf = [0u8; Self::BYTES_REPR_SIZE];
        let mut order = BIG::new_ints(&CURVE_ORDER);
        order.tobytes(&mut buf);
        BigNumber::from_bytes(&buf)
    }

    pub fn is_zero(&self) -> bool {
        self.bn.iszilch()
    }

    pub fn new_from_seed(seed: &[u8]) -> ClResult<GroupOrderElement> {
        // returns random element in 0, ..., GroupOrder-1
        if seed.len() != MODBYTES {
            return Err(err_msg!("Invalid byte length for seed"));
        }
        let mut rng = RAND::new();
        rng.seed(seed.len(), seed);

        Ok(GroupOrderElement {
            bn: BIG::randomnum(&ORDER, &mut rng),
        })
    }

    /// (GroupOrderElement ^ GroupOrderElement) mod GroupOrder
    pub fn pow_mod(&self, e: &GroupOrderElement) -> ClResult<GroupOrderElement> {
        let mut base = self.bn;
        Ok(GroupOrderElement {
            bn: base.powmod(&e.bn, &ORDER),
        })
    }

    /// (GroupOrderElement + GroupOrderElement) mod GroupOrder
    pub fn add_mod(&self, r: &GroupOrderElement) -> ClResult<GroupOrderElement> {
        let mut sum = self.bn;
        sum.add(&r.bn);
        sum.rmod(&ORDER);
        sum.norm();
        Ok(GroupOrderElement { bn: sum })
    }

    /// (GroupOrderElement - GroupOrderElement) mod GroupOrder
    pub fn sub_mod(&self, r: &GroupOrderElement) -> ClResult<GroupOrderElement> {
        let mut sum = self.bn;
        sum.add(&ORDER);
        sum.sub(&r.bn);
        sum.rmod(&ORDER);
        sum.norm();
        Ok(GroupOrderElement { bn: sum })
    }

    /// (GroupOrderElement * GroupOrderElement) mod GroupOrder
    pub fn mul_mod(&self, r: &GroupOrderElement) -> ClResult<GroupOrderElement> {
        Ok(GroupOrderElement {
            bn: BIG::modmul(&self.bn, &r.bn, &ORDER),
        })
    }

    /// 1 / GroupOrderElement
    pub fn inverse(&self) -> ClResult<GroupOrderElement> {
        let mut bn = self.bn;
        bn.invmodp(&ORDER);
        Ok(GroupOrderElement { bn })
    }

    /// - GroupOrderElement mod GroupOrder
    pub fn mod_neg(&self) -> ClResult<GroupOrderElement> {
        let mut bn = self.bn;
        bn.rmod(&ORDER);
        bn.rsub(&ORDER);
        bn.norm();
        Ok(GroupOrderElement { bn })
    }

    pub fn to_string(&self) -> ClResult<String> {
        let mut bn = self.bn;
        Ok(bn.to_hex())
    }

    pub fn from_string(str: &str) -> ClResult<GroupOrderElement> {
        let mut bn = BIG::from_hex(str.to_string());
        bn.rmod(&ORDER);
        bn.norm();
        Ok(GroupOrderElement { bn })
    }

    pub fn to_bytes(&self) -> ClResult<Vec<u8>> {
        let mut bn = self.bn;
        let mut vec = vec![0u8; Self::BYTES_REPR_SIZE];
        bn.tobytes(&mut vec);
        Ok(vec)
    }

    pub fn from_bytes(b: &[u8]) -> ClResult<GroupOrderElement> {
        if b.len() > Self::BYTES_REPR_SIZE {
            return Err(err_msg!("Invalid byte length for GroupOrderElement"));
        }
        let mut buf = [0u8; Self::BYTES_REPR_SIZE];
        buf[(Self::BYTES_REPR_SIZE - b.len())..].copy_from_slice(b);
        let mut bn = BIG::frombytes(&buf);
        bn.rmod(&BIG::new_ints(&CURVE_ORDER));
        bn.norm();
        Ok(GroupOrderElement { bn })
    }
}

impl Debug for GroupOrderElement {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut bn = self.bn;
        write!(f, "GroupOrderElement {{ bn: {} }}", bn.to_hex())
    }
}

#[cfg(feature = "serde")]
impl Serialize for GroupOrderElement {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_newtype_struct(
            "GroupOrderElement",
            &self.to_string().map_err(serde::ser::Error::custom)?,
        )
    }
}

#[cfg(feature = "serde")]
impl<'a> Deserialize<'a> for GroupOrderElement {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'a>,
    {
        deserializer.deserialize_str(StrVisitor("expected GroupOrderElement", Self::from_string))
    }
}

#[derive(Copy, Clone, PartialEq)]
pub struct Pair {
    pair: FP12,
}

impl Pair {
    pub const BYTES_REPR_SIZE: usize = MODBYTES * 16;

    /// e(PointG1, PointG2)
    pub fn pair(p: &PointG1, q: &PointG2) -> ClResult<Self> {
        let mut result = fexp(&ate(&q.point, &p.point));
        result.reduce();

        Ok(Self { pair: result })
    }

    /// e(PointG1, PointG2, PointG1_1, PointG2_1)
    pub fn pair2(p: &PointG1, q: &PointG2, r: &PointG1, s: &PointG2) -> ClResult<Self> {
        let mut result = fexp(&ate2(&q.point, &p.point, &s.point, &r.point));
        result.reduce();

        Ok(Self { pair: result })
    }

    #[allow(unused)]
    pub fn new_unity() -> ClResult<Self> {
        Ok(Self {
            pair: FP12::new_int(1),
        })
    }

    /// e() * e()
    pub fn mul(&self, b: &Pair) -> ClResult<Pair> {
        let mut base = self.pair;
        base.mul(&b.pair);
        base.reduce();
        Ok(Pair { pair: base })
    }

    /// e() ^ GroupOrderElement
    pub fn pow(&self, b: &GroupOrderElement) -> ClResult<Pair> {
        Ok(Pair {
            pair: gtpow(&self.pair, &b.bn),
        })
    }

    /// 1 / e()
    pub fn inverse(&self) -> ClResult<Pair> {
        let mut r = self.pair;
        r.conj();
        Ok(Pair { pair: r })
    }

    pub fn is_unity(&self) -> ClResult<bool> {
        Ok(self.pair.isunity())
    }

    pub fn to_string(&self) -> ClResult<String> {
        Ok(self.pair.to_hex())
    }

    pub fn from_string(val: &str) -> ClResult<Pair> {
        pre_validate_point(val, 12)?;
        let pair = FP12::from_hex(val.to_string());
        if is_valid_pair(&pair) {
            Ok(Pair { pair })
        } else {
            Err(err_msg!("Invalid pair"))
        }
    }

    pub fn to_bytes(&self) -> ClResult<Vec<u8>> {
        let mut r = self.pair;
        let mut vec = vec![0u8; Self::BYTES_REPR_SIZE];
        r.tobytes(&mut vec);
        Ok(vec)
    }
}

impl Debug for Pair {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Pair {{ pair: {} }}", self.pair.to_hex())
    }
}

#[cfg(feature = "serde")]
impl Serialize for Pair {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_newtype_struct(
            "Pair",
            &self.to_string().map_err(serde::ser::Error::custom)?,
        )
    }
}

#[cfg(feature = "serde")]
impl<'a> Deserialize<'a> for Pair {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'a>,
    {
        deserializer.deserialize_str(StrVisitor("expected Pair", Self::from_string))
    }
}

fn pre_validate_point(val: &str, components: usize) -> ClResult<()> {
    let mut parts = val.split_ascii_whitespace();
    let mut idx = 0;
    let valid = loop {
        if idx == components {
            break parts.next().is_none();
        }
        if let Some(idx) = parts.next() {
            match idx.parse::<u32>() {
                Ok(0) | Err(_) => break false,
                Ok(_) => {}
            }
        } else {
            break false;
        }
        if let Some(hex) = parts.next() {
            if validate_hex(hex.as_bytes()).is_none() {
                break false;
            }
        } else {
            break false;
        }
        idx += 1;
    };
    if valid {
        Ok(())
    } else {
        Err(err_msg!("Invalid point value"))
    }
}

const fn validate_hex(bytes: &[u8]) -> Option<usize> {
    let mut i = 0;
    while i < bytes.len() {
        if !matches!(bytes[i], b'0'..=b'9' | b'a' ..= b'f' | b'A'..=b'F') {
            return None;
        }
        i += 1;
    }
    Some((bytes.len() + 1) / 2)
}

fn is_valid_ecp(point: &ECP) -> bool {
    // validate point without inverting z:
    // (y/z)^2 = (x/z)^3 + b  -->  y^2z = x^3 + bz^3
    let (x, z) = (point.getpx(), point.getpz());
    let mut lhs = point.getpy();
    lhs.reduce();
    lhs.sqr();
    lhs.mul(&z);
    let mut rhs = x;
    rhs.reduce();
    rhs.sqr();
    rhs.mul(&x);
    lhs.sub(&rhs);
    rhs.copy(&z);
    rhs.reduce();
    rhs.sqr();
    rhs.mul(&z);
    rhs.dbl(); // b = 2
    lhs.equals(&rhs)
}

fn is_valid_ecp2(point: &ECP2) -> bool {
    // validate point without inverting z:
    // (y/z)^2 = (x/z)^3 + b'  -->  y^2z = x^3 + b'z^3
    let (x, z) = (point.getpx(), point.getpz());
    let mut lhs = point.getpy();
    lhs.reduce();
    lhs.norm();
    lhs.sqr();
    lhs.norm();
    lhs.mul(&z);
    let mut rhs = x;
    rhs.reduce();
    rhs.sqr();
    rhs.mul(&x);
    lhs.sub(&rhs);
    rhs.copy(&z);
    rhs.reduce();
    rhs.sqr();
    rhs.mul(&z);
    let bp = FP2::new_fps(&FP::new_int(1), &FP::new_int(-1)); // b' = b/ξ = 1 - i
    rhs.mul(&bp);
    lhs.equals(&rhs)
}

fn is_valid_pair(point: &FP12) -> bool {
    // Subgroup security in pairing-based cryptography
    // Section 5.2  https://eprint.iacr.org/2015/247
    // Check that g^(p^4 - p^2 + 1) = 1  ==>  g^(p^4 + 1) == g^(p^2)
    let f = FP2::new_bigs(
        &BIG::new_ints(&amcl::bn254::rom::FRA),
        &BIG::new_ints(&amcl::bn254::rom::FRB),
    );
    let mut lhs = *point;
    lhs.frob(&f);
    lhs.frob(&f);
    let mut rhs = lhs;
    rhs.frob(&f);
    rhs.frob(&f);
    rhs.mul(point);
    lhs.equals(&rhs)
}

#[cfg(feature = "serde")]
#[derive(Debug)]
pub(crate) struct StrVisitor<F>(pub &'static str, pub F);

#[cfg(feature = "serde")]
impl<'d, F, T> Visitor<'d> for StrVisitor<F>
where
    F: FnOnce(&str) -> ClResult<T>,
{
    type Value = T;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.1(value).map_err(E::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_order_element_new_from_seed_works_for_invalid_seed_len() {
        let res = GroupOrderElement::new_from_seed(&[0, 1, 2]);
        assert!(res.is_err());
    }

    #[test]
    fn group_order_element_sub_mod() {
        let res = GroupOrderElement::new().unwrap();
        assert_eq!(
            res.sub_mod(&res.mod_neg().unwrap()).unwrap(),
            res.add_mod(&res).unwrap()
        );
        assert_eq!(
            res.mod_neg().unwrap().sub_mod(&res).unwrap(),
            res.add_mod(&res).unwrap().mod_neg().unwrap()
        );
        assert_eq!(
            res.sub_mod(&res).unwrap(),
            GroupOrderElement::zero().unwrap()
        );
    }

    #[test]
    fn pairing_definition_bilinearity() {
        let a = GroupOrderElement::new().unwrap();
        let b = GroupOrderElement::new().unwrap();
        let p = PointG1::new().unwrap();
        let q = PointG2::new().unwrap();
        let left = Pair::pair(&p.mul(&a).unwrap(), &q.mul(&b).unwrap()).unwrap();
        let right = Pair::pair(&p, &q)
            .unwrap()
            .pow(&a.mul_mod(&b).unwrap())
            .unwrap();
        assert_eq!(left, right);
    }

    #[test]
    fn point_g1_infinity_test() {
        let p = PointG1::new_inf().unwrap();
        let q = PointG1::new().unwrap();
        let result = p.add(&q).unwrap();
        assert_eq!(q, result);
    }

    #[test]
    fn point_g1_infinity_test2() {
        let p = PointG1::new().unwrap();
        let inf = p.sub(&p).unwrap();
        let q = PointG1::new().unwrap();
        let result = inf.add(&q).unwrap();
        assert_eq!(q, result);
    }

    #[test]
    fn point_g2_infinity_test() {
        let p = PointG2::new_inf().unwrap();
        let q = PointG2::new().unwrap();
        let result = p.add(&q).unwrap();
        assert_eq!(q, result);
    }

    #[test]
    fn inverse_for_pairing() {
        let p1 = PointG1::new().unwrap();
        let q1 = PointG2::new().unwrap();
        let p2 = PointG1::new().unwrap();
        let q2 = PointG2::new().unwrap();
        let pair1 = Pair::pair(&p1, &q1).unwrap();
        let pair2 = Pair::pair(&p2, &q2).unwrap();
        let pair_result = pair1.mul(&pair2).unwrap();
        let pair3 = pair_result.mul(&pair1.inverse().unwrap()).unwrap();
        assert_eq!(pair2, pair3);

        let r = GroupOrderElement::new().unwrap();
        assert_eq!(
            Pair::pair(&p1.mul(&r).unwrap(), &q1)
                .unwrap()
                .inverse()
                .unwrap(),
            Pair::pair(&p1.mul(&r.mod_neg().unwrap()).unwrap(), &q1).unwrap()
        );
    }
}

#[cfg(feature = "serde")]
#[cfg(test)]
mod serialization_tests {
    use super::*;

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct TestGroupOrderElementStructure {
        field: GroupOrderElement,
    }

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct TestPointG1Structure {
        field: PointG1,
    }

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct TestPointG2Structure {
        field: PointG2,
    }

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct TestPairStructure {
        field: Pair,
    }

    #[test]
    fn from_bytes_to_bytes_works_for_group_order_element() {
        let vec = vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 116, 221, 243, 243, 0, 77, 170, 65,
            179, 245, 119, 182, 251, 185, 78, 98,
        ];
        let bytes = GroupOrderElement::from_bytes(&vec).unwrap();
        let result = bytes.to_bytes().unwrap();
        assert_eq!(vec, result);
    }

    #[test]
    fn serialize_deserialize_works_for_group_order_element() {
        let structure = TestGroupOrderElementStructure {
            field: GroupOrderElement::from_string(
                "09181F00DD41F2F92026FC20E189DE31926EEE6E05C6A17E676556E08075C6111",
            )
            .unwrap(),
        };
        let deserialized: TestGroupOrderElementStructure =
            serde_json::from_str(&serde_json::to_string(&structure).unwrap()).unwrap();

        assert_eq!(structure, deserialized);
    }

    #[test]
    fn serialize_deserialize_works_for_point_g1() {
        let structure = TestPointG1Structure {
            field: PointG1::from_string("1 1D18E69FA5AA97421F4AEBE933B40264261C5440090222C6AC61FEBE2CFEAA04 1 1461756FB88E41A2CB508A7057318CAFB551F4CD0C7051CBEC23DDFBC92248BC 1 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8").unwrap()
        };
        let deserialized: TestPointG1Structure =
            serde_json::from_str(&serde_json::to_string(&structure).unwrap()).unwrap();
        assert_eq!(structure, deserialized);

        // check invalid input
        assert!(PointG1::from_string(",").is_err());
        // check non-subgroup point
        assert!(PointG1::from_string("1 09181F00DD41F2F92026FC20E189DE31926EEE6E05C6A17E676556E08075C6 1 09BC971251F977993486B19600760C4F972925D98934EA6B2D0BEC671398C0 1 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8").is_err());
        // check disallowed infinity
        assert!(PointG1::from_string("1 0000000000000000000000000000000000000000000000000000000000000000 2 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8 1 0000000000000000000000000000000000000000000000000000000000000000").is_err());
        // check allowed infinity
        assert!(PointG1::from_string_inf("1 0000000000000000000000000000000000000000000000000000000000000000 2 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8 1 0000000000000000000000000000000000000000000000000000000000000000").is_ok());
    }

    #[test]
    fn deserialize_works_for_point_g2() {
        let structure = TestPointG2Structure {
            field: PointG2::from_string("1 1045C93522D11FB9EB69396032EEA008B857C7F8B3F2981C9917B1DFA8A00EC9 1 01AD44557A4240BB570FB94B33746C272CF921F33B4910B111F1CA48FCE34FC2 1 2265EAFAED9C22CD76C2FBD6FC3B88414B6B66FB4E31FCD1ED6AADE25A9D31EB 1 234B062F5159CB2E0782CFB75478E45D46EBF0F21E3CE7A2CD758687A73D5D08 1 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8 1 0000000000000000000000000000000000000000000000000000000000000000").unwrap()
        };
        let deserialized: TestPointG2Structure =
            serde_json::from_str(&serde_json::to_string(&structure).unwrap()).unwrap();
        assert_eq!(structure, deserialized);

        // check invalid input
        assert!(PointG2::from_string(",").is_err());
        // check non-subgroup point
        assert!(PointG2::from_string("1 16027A65C15E16E00BFCAD948F216B5CFBE07B98876D8889A5DEE03DE7C57B 1 0EC9DBC2286A9485A0DA8525C5BE0F88E27C2B3C337E522DDC170C1764D615 1 1A021C8EFE70DCC7F81DD8E8CDC74F3D64E63E886C73B3A8B9849696E99FF3 1 2505CB0CFAAE75ACCAF60CB5A9F7E7A8250918155886E7FFF9A32D7B5A0500 1 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8 1 00000000000000000000000000000000000000000000000000000000000000").is_err());
        // check disallowed infinity
        assert!(PointG2::from_string("1 0000000000000000000000000000000000000000000000000000000000000000 1 0000000000000000000000000000000000000000000000000000000000000000 2 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8 1 0000000000000000000000000000000000000000000000000000000000000000 1 0000000000000000000000000000000000000000000000000000000000000000 1 0000000000000000000000000000000000000000000000000000000000000000").is_err());
        // check allowed infinity
        assert!(PointG2::from_string_inf("1 0000000000000000000000000000000000000000000000000000000000000000 1 0000000000000000000000000000000000000000000000000000000000000000 2 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8 1 0000000000000000000000000000000000000000000000000000000000000000 1 0000000000000000000000000000000000000000000000000000000000000000 1 0000000000000000000000000000000000000000000000000000000000000000").is_ok());
    }

    #[test]
    fn deserialize_works_for_big_sum() {
        let mut big = ECP2::from_hex("1 7A574E39839EBC8E7F8D567865D5D9AAC54952659F0E393BE35C7FC3BE93CDA6 1 AFB9BF4A3B655BFFDC89C14720101773569FDD36A67440AEB7C2FFB861B74025 1 1F25D2A75390350C9C77DE886B503D5EA2CC3685037460F9CF93601BFA88028E 1 306E80C709AAA293B8D2AAABF04838C8AB96BFB3F8E0C4A89940D227A8BF8B01 1 6867E792BBE850A8716C97F7140D95FD6DB76C5DB0F4876E800B18E2CB0226B3 1 427CB9FC452B316239ABCA9C0078E5F36B4E9FC777B6D91587BB7DA64C1C1E94".to_string());
        let mut big_2 = big.clone();
        big.add(&mut big_2);
        let deserialized = ECP2::from_hex(big.to_hex());
        assert_eq!(deserialized, big);
    }

    #[test]
    fn serialize_deserialize_works_for_pair() {
        let point_g1 = PointG1 {
            point: PointG1::from_string("1 1D18E69FA5AA97421F4AEBE933B40264261C5440090222C6AC61FEBE2CFEAA04 1 1461756FB88E41A2CB508A7057318CAFB551F4CD0C7051CBEC23DDFBC92248BC 1 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8").unwrap().point
        };
        let point_g2 = PointG2 {
            point: PointG2::from_string("1 1045C93522D11FB9EB69396032EEA008B857C7F8B3F2981C9917B1DFA8A00EC9 1 01AD44557A4240BB570FB94B33746C272CF921F33B4910B111F1CA48FCE34FC2 1 2265EAFAED9C22CD76C2FBD6FC3B88414B6B66FB4E31FCD1ED6AADE25A9D31EB 1 234B062F5159CB2E0782CFB75478E45D46EBF0F21E3CE7A2CD758687A73D5D08 1 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8 1 0000000000000000000000000000000000000000000000000000000000000000").unwrap().point
        };
        let pair = TestPairStructure {
            field: Pair::pair(&point_g1, &point_g2).unwrap(),
        };
        let deserialized: TestPairStructure =
            serde_json::from_str(&serde_json::to_string(&pair).unwrap()).unwrap();
        assert_eq!(pair, deserialized);

        // check invalid input
        assert!(Pair::from_string(",").is_err());
        // check non-subgroup point
        assert!(Pair::from_string("1 1A0FB1F80E3C1FB1D99656B1B6DDF183D5EF4760838C68B088E892C846B7DC2C 1 1235B7EF46F16A30D6481B2A63E672EBCD931DFE1FE8B4101EA6F8A65FBDCD05 1 02CFBC531AD1C591ACC4F90806D4C8D1D2E7CA1701281076E62DFDFCB743ED0F 1 2472470CB4C5E83208F7CB8FA1C2AFE168CE964EAC3AA0F00D0F851B9BFD640B 1 15010B4BD62468BB8D19513CA350D731E47E034570164DFAE0939F2540FE6132 1 145BB54DDFB66D9C48655F9F7700CC2A341A7BB0B73BA0271927D23A1C9F80A0 1 236FB4C3A3500BF02E7A95A8041ED9C789D57DE3EB9952F773EF8C35953B1FA9 1 152902DA32832510A0DBDE0BE32F6E0DC01374D0DA5B00B30E7A5DFEDF9DE0C7 1 15A9F25FC4079A513FA5B1982AE2808F5D577A8CAE17A030B03B3B10E4606449 1 0CCF8D3EF066E5C4C79106F0A4A5490DD69507161510E56CA43FA304277D2DC7 1 14AB69814995CABA1A07C0B5F8A75B27074CA5CD4213974007B866E0BFE3CA06 1 0151272518EBB8E894FEFB11E19BB4D748F31213DB50454659E1011C2B73FC7C").is_err());
        // check unity
        assert!(Pair::from_string("2 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8 1 0000000000000000000000000000000000000000000000000000000000000000 1 0000000000000000000000000000000000000000000000000000000000000000 1 0000000000000000000000000000000000000000000000000000000000000000 1 0000000000000000000000000000000000000000000000000000000000000000 1 0000000000000000000000000000000000000000000000000000000000000000 1 0000000000000000000000000000000000000000000000000000000000000000 1 0000000000000000000000000000000000000000000000000000000000000000 1 0000000000000000000000000000000000000000000000000000000000000000 1 0000000000000000000000000000000000000000000000000000000000000000 1 0000000000000000000000000000000000000000000000000000000000000000 1 0000000000000000000000000000000000000000000000000000000000000000").unwrap().is_unity().unwrap());
    }
}
