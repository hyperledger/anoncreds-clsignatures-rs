use std::cmp::Ord;
use std::cmp::Ordering;
use std::fmt;

use glass_pumpkin::{prime, safe_prime};
use num_bigint::{BigInt, RandBigInt, Sign, ToBigInt};
use num_integer::Integer;
use num_traits::identities::{One, Zero};
use num_traits::{Num, Pow, Signed, ToPrimitive};
use rand::rngs::OsRng;

#[cfg(feature = "serde")]
use serde::{de::Visitor, Deserialize, Deserializer, Serialize, Serializer};

use crate::error::{Error as ClError, Result as ClResult};

#[derive(Debug)]
pub struct BigNumberContext;

pub struct BigNumber {
    bn: BigInt,
}

macro_rules! prime_generation {
    ($f:ident, $size:ident, $msg:expr) => {
        match $f::new($size)?.to_bigint() {
            Some(bn) => Ok(BigNumber { bn }),
            None => Err(err_msg!($msg)),
        }
    };
}

macro_rules! prime_check {
    ($f:ident, $value:expr, $msg:expr) => {
        if $value.is_negative() {
            Ok(false)
        } else {
            match $value.bn.to_biguint() {
                Some(bn) => Ok($f::check(&bn)),
                None => Err(err_msg!($msg)),
            }
        }
    };
}

impl BigNumber {
    pub fn new_context() -> ClResult<BigNumberContext> {
        Ok(BigNumberContext {})
    }

    pub fn new() -> ClResult<BigNumber> {
        Ok(BigNumber { bn: BigInt::zero() })
    }

    pub fn generate_prime(size: usize) -> ClResult<BigNumber> {
        prime_generation!(prime, size, "Unable to generate prime")
    }

    pub fn generate_safe_prime(size: usize) -> ClResult<BigNumber> {
        prime_generation!(safe_prime, size, "Unable to generate safe prime")
    }

    pub fn is_prime(&self, _ctx: Option<&mut BigNumberContext>) -> ClResult<bool> {
        prime_check!(prime, self, "An error in is_prime")
    }

    pub fn is_safe_prime(&self, _ctx: Option<&mut BigNumberContext>) -> ClResult<bool> {
        prime_check!(safe_prime, self, "An error in is_safe_prime")
    }

    pub fn rand(size: usize) -> ClResult<BigNumber> {
        let mut rng = OsRng::default();
        let res = rng.gen_biguint(size as u64).to_bigint();
        Ok(BigNumber { bn: res.unwrap() })
    }

    pub fn rand_range(&self) -> ClResult<BigNumber> {
        let mut rng = OsRng::default();
        let res = rng.gen_bigint_range(&BigInt::zero(), &self.bn);
        match res.to_bigint() {
            Some(bn) => Ok(BigNumber { bn }),
            None => Err(err_msg!("An error occurred in rand_range")),
        }
    }

    pub fn num_bits(&self) -> ClResult<i32> {
        Ok(self.bn.bits() as i32)
    }

    pub fn is_bit_set(&self, n: i32) -> ClResult<bool> {
        let bits = n as usize;
        let res = &self.bn >> bits;
        Ok(res.is_odd())
    }

    pub fn set_bit(&mut self, n: i32) -> Result<&mut BigNumber, ClError> {
        let bits = n as usize;
        let mask = BigInt::one() << bits;
        self.bn |= mask;
        Ok(self)
    }

    pub fn from_u32(n: usize) -> ClResult<BigNumber> {
        Ok(BigNumber {
            bn: BigInt::from(n),
        })
    }

    pub fn from_dec(dec: &str) -> ClResult<BigNumber> {
        Ok(BigNumber {
            bn: BigInt::from_str_radix(dec, 10)?,
        })
    }

    pub fn from_hex(hex: &str) -> ClResult<BigNumber> {
        Ok(BigNumber {
            bn: BigInt::from_str_radix(hex, 16)?,
        })
    }

    pub fn from_bytes(bytes: &[u8]) -> ClResult<BigNumber> {
        Ok(BigNumber {
            bn: BigInt::from_bytes_be(Sign::Plus, bytes),
        })
    }

    pub fn to_dec(&self) -> ClResult<String> {
        Ok(self.bn.to_str_radix(10))
    }

    pub fn to_hex(&self) -> ClResult<String> {
        Ok(self.bn.to_str_radix(16).to_uppercase())
    }

    pub fn to_bytes(&self) -> ClResult<Vec<u8>> {
        let (_, res) = self.bn.to_bytes_be();
        Ok(res)
    }

    pub fn add(&self, a: &BigNumber) -> ClResult<BigNumber> {
        let res = &self.bn + &a.bn;
        Ok(BigNumber { bn: res })
    }

    pub fn sub(&self, a: &BigNumber) -> ClResult<BigNumber> {
        let res = &self.bn - &a.bn;
        Ok(BigNumber { bn: res })
    }

    pub fn sqr(&self, _ctx: Option<&mut BigNumberContext>) -> ClResult<BigNumber> {
        let res = &self.bn * &self.bn;
        Ok(BigNumber { bn: res })
    }

    pub fn mul(&self, a: &BigNumber, _ctx: Option<&mut BigNumberContext>) -> ClResult<BigNumber> {
        let res = &self.bn * &a.bn;
        Ok(BigNumber { bn: res })
    }

    pub fn mod_mul(
        &self,
        a: &BigNumber,
        n: &BigNumber,
        _ctx: Option<&mut BigNumberContext>,
    ) -> ClResult<BigNumber> {
        //TODO: Use montgomery reduction
        self.mul(&a, None)?.modulus(&n, None)
    }

    pub fn mod_sub(
        &self,
        a: &BigNumber,
        n: &BigNumber,
        _ctx: Option<&mut BigNumberContext>,
    ) -> ClResult<BigNumber> {
        self.sub(&a)?.modulus(&n, None)
    }

    pub fn div(&self, a: &BigNumber, _ctx: Option<&mut BigNumberContext>) -> ClResult<BigNumber> {
        if a.bn.is_zero() {
            Err(err_msg!("divisor cannot be zero"))
        } else {
            let res = &self.bn / &a.bn;
            Ok(BigNumber { bn: res })
        }
    }

    pub fn gcd(
        a: &BigNumber,
        b: &BigNumber,
        _ctx: Option<&mut BigNumberContext>,
    ) -> ClResult<BigNumber> {
        Ok(BigNumber {
            bn: a.bn.gcd(&b.bn),
        })
    }

    pub fn add_word(&mut self, w: u32) -> Result<&mut BigNumber, ClError> {
        self.bn += w;
        Ok(self)
    }

    pub fn sub_word(&mut self, w: u32) -> Result<&mut BigNumber, ClError> {
        self.bn -= w;
        Ok(self)
    }

    pub fn mul_word(&mut self, w: u32) -> Result<&mut BigNumber, ClError> {
        self.bn *= w;
        Ok(self)
    }

    pub fn div_word(&mut self, w: u32) -> Result<&mut BigNumber, ClError> {
        if w == 0 {
            Err(err_msg!("divisor cannot be zero"))
        } else {
            self.bn /= w;
            Ok(self)
        }
    }

    pub fn mod_exp(
        &self,
        a: &BigNumber,
        b: &BigNumber,
        _ctx: Option<&mut BigNumberContext>,
    ) -> ClResult<BigNumber> {
        if b.bn.is_one() {
            return BigNumber::new();
        }

        if a.is_negative() {
            let res = self.inverse(&b, _ctx)?;
            let a = a.set_negative(false)?;
            Ok(BigNumber {
                bn: res.bn.modpow(&a.bn, &BigNumber::_get_modulus(&b.bn)),
            })
        } else {
            let res = self.bn.modpow(&a.bn, &BigNumber::_get_modulus(&b.bn));
            Ok(BigNumber { bn: res })
        }
    }

    pub fn modulus(
        &self,
        a: &BigNumber,
        _ctx: Option<&mut BigNumberContext>,
    ) -> ClResult<BigNumber> {
        if a.bn.is_zero() {
            return Err(err_msg!("Invalid modulus"));
        }
        let n = BigNumber::_get_modulus(&a.bn);
        let mut res = &self.bn % &n;
        if res < BigInt::zero() {
            res += n;
        }
        Ok(BigNumber { bn: res })
    }

    fn _get_modulus(bn: &BigInt) -> BigInt {
        if bn.is_positive() {
            bn.clone()
        } else {
            -bn.clone()
        }
    }

    pub fn exp(&self, a: &BigNumber, _ctx: Option<&mut BigNumberContext>) -> ClResult<BigNumber> {
        if self.bn.bits() == 0 {
            return Ok(BigNumber::default());
        } else if a.bn.is_one() {
            return Ok(self.try_clone()?);
        }

        match a.bn.to_u64() {
            Some(num) => Ok(BigNumber {
                bn: self.bn.clone().pow(num),
            }),
            None => Err(err_msg!("exponent is not an integer (u64)")),
        }
    }

    pub fn inverse(
        &self,
        n: &BigNumber,
        _ctx: Option<&mut BigNumberContext>,
    ) -> ClResult<BigNumber> {
        if n.bn.is_one() || n.bn.is_zero() {
            return Err(err_msg!("Invalid modulus"));
        }
        let n = BigNumber::_get_modulus(&n.bn);

        // Euclid's extended algorithm, Bèzout coefficient of `n` is not needed
        //n is either prime or coprime
        //
        //function inverse(a, n)
        //    t := 0;     newt := 1;
        //    r := n;     newr := a;
        //    while newr ≠ 0
        //        quotient := r div newr
        //        (t, newt) := (newt, t - quotient * newt)
        //        (r, newr) := (newr, r - quotient * newr)
        //    if r > 1 then return "a is not invertible"
        //    if t < 0 then t := t + n
        //    return t
        //
        let (mut t, mut new_t) = (BigInt::zero(), BigInt::one());
        let (mut r, mut new_r) = (n.clone(), self.bn.clone());

        while !new_r.is_zero() {
            let quotient = &r / &new_r;
            let temp_t = t.clone();
            let temp_new_t = new_t.clone();

            t = temp_new_t.clone();
            new_t = temp_t - &quotient * temp_new_t;

            let temp_r = r.clone();
            let temp_new_r = new_r.clone();

            r = temp_new_r.clone();
            new_r = temp_r - quotient * temp_new_r;
        }
        if r > BigInt::one() {
            return Err(err_msg!("Not invertible"));
        } else if t < BigInt::zero() {
            t += n.clone()
        }

        Ok(BigNumber { bn: t })
    }

    pub fn set_negative(&self, negative: bool) -> ClResult<BigNumber> {
        match (self.bn < BigInt::zero(), negative) {
            (true, true) => Ok(BigNumber {
                bn: self.bn.clone(),
            }),
            (false, false) => Ok(BigNumber {
                bn: self.bn.clone(),
            }),
            (true, false) => Ok(BigNumber {
                bn: -self.bn.clone(),
            }),
            (false, true) => Ok(BigNumber {
                bn: -self.bn.clone(),
            }),
        }
    }

    pub fn is_negative(&self) -> bool {
        self.bn.is_negative()
    }

    pub fn increment(&self) -> ClResult<BigNumber> {
        Ok(BigNumber { bn: &self.bn + 1 })
    }

    pub fn decrement(&self) -> ClResult<BigNumber> {
        Ok(BigNumber { bn: &self.bn - 1 })
    }

    pub fn lshift1(&self) -> ClResult<BigNumber> {
        Ok(BigNumber { bn: &self.bn << 1 })
    }

    pub fn rshift1(&self) -> ClResult<BigNumber> {
        Ok(BigNumber { bn: &self.bn >> 1 })
    }

    pub fn rshift(&self, n: u32) -> ClResult<BigNumber> {
        let n = n as usize;
        Ok(BigNumber { bn: &self.bn >> n })
    }

    pub fn mod_div(
        &self,
        b: &BigNumber,
        p: &BigNumber,
        _ctx: Option<&mut BigNumberContext>,
    ) -> ClResult<BigNumber> {
        //(a * (1/b mod p) mod p)
        self.mul(&b.inverse(&p, None)?, None)?.modulus(&p, None)
    }

    pub fn random_qr(n: &BigNumber) -> ClResult<BigNumber> {
        let qr = n.rand_range()?.sqr(None)?.modulus(&n, None)?;
        Ok(qr)
    }

    pub fn try_clone(&self) -> ClResult<BigNumber> {
        Ok(BigNumber {
            bn: self.bn.clone(),
        })
    }
}

impl fmt::Debug for BigNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BigNumber {{ bn: {} }}", self.bn.to_str_radix(10))
    }
}

impl fmt::Display for BigNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BigNumber {{ bn: {} }}", self.bn.to_str_radix(10))
    }
}

impl Ord for BigNumber {
    fn cmp(&self, other: &BigNumber) -> Ordering {
        self.bn.cmp(&other.bn)
    }
}

impl Eq for BigNumber {}

impl PartialOrd for BigNumber {
    fn partial_cmp(&self, other: &BigNumber) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for BigNumber {
    fn eq(&self, other: &BigNumber) -> bool {
        self.bn == other.bn
    }
}

#[cfg(feature = "serde")]
impl Serialize for BigNumber {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_newtype_struct(
            "BigNumber",
            &self.to_dec().map_err(serde::ser::Error::custom)?,
        )
    }
}

#[cfg(feature = "serde")]
impl<'a> Deserialize<'a> for BigNumber {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'a>,
    {
        struct BigNumberVisitor;

        impl<'a> Visitor<'a> for BigNumberVisitor {
            type Value = BigNumber;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("expected BigNumber")
            }

            fn visit_str<E>(self, value: &str) -> Result<BigNumber, E>
            where
                E: serde::de::Error,
            {
                Ok(BigNumber::from_dec(value).map_err(E::custom)?)
            }
        }

        deserializer.deserialize_str(BigNumberVisitor)
    }
}

impl From<glass_pumpkin::error::Error> for ClError {
    fn from(err: glass_pumpkin::error::Error) -> ClError {
        err_msg!("Internal Prime Generation error: {}", err)
    }
}

impl From<rand::Error> for ClError {
    fn from(err: rand::Error) -> ClError {
        err_msg!("Internal Random Number error: {}", err)
    }
}

impl From<num_bigint::ParseBigIntError> for ClError {
    fn from(err: num_bigint::ParseBigIntError) -> ClError {
        err_msg!("Internal Parse BigInt error: {}", err)
    }
}

impl Default for BigNumber {
    fn default() -> BigNumber {
        BigNumber { bn: BigInt::zero() }
    }
}
