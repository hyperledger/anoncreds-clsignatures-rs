use std::cmp::Ord;
use std::cmp::Ordering;
use std::fmt;

use openssl::bn::{BigNum, BigNumContext, BigNumRef, MsbOption};
use openssl::error::ErrorStack;

#[cfg(feature = "serde")]
use serde::{de::Visitor, Deserialize, Deserializer, Serialize, Serializer};

use crate::error::{Error as ClError, Result as ClResult};

pub struct BigNumberContext {
    openssl_bn_context: BigNumContext,
}

impl fmt::Debug for BigNumberContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BigNumberContext")
    }
}

#[derive(Debug)]
pub struct BigNumber {
    openssl_bn: BigNum,
}

impl BigNumber {
    pub fn new_context() -> ClResult<BigNumberContext> {
        let ctx = BigNumContext::new_secure()?;
        Ok(BigNumberContext {
            openssl_bn_context: ctx,
        })
    }

    pub fn new() -> ClResult<BigNumber> {
        let bn = BigNum::new_secure()?;
        Ok(BigNumber { openssl_bn: bn })
    }

    pub fn generate_prime(size: usize) -> ClResult<BigNumber> {
        let mut bn = BigNumber::new()?;
        BigNumRef::generate_prime(&mut bn.openssl_bn, size as i32, false, None, None)?;
        Ok(bn)
    }

    pub fn generate_safe_prime(size: usize) -> ClResult<BigNumber> {
        let mut bn = BigNumber::new()?;
        BigNumRef::generate_prime(&mut bn.openssl_bn, (size + 1) as i32, true, None, None)?;
        Ok(bn)
    }

    pub fn is_prime(&self, ctx: Option<&mut BigNumberContext>) -> ClResult<bool> {
        let prime_len = self.openssl_bn.num_bits() as f32 * core::f32::consts::LOG10_2;
        let checks = prime_len.log2() as i32;
        match ctx {
            Some(context) => Ok(self.openssl_bn.is_prime_fasttest(
                checks,
                &mut context.openssl_bn_context,
                true,
            )?),
            None => {
                let mut ctx = BigNumber::new_context()?;
                Ok(self
                    .openssl_bn
                    .is_prime_fasttest(checks, &mut ctx.openssl_bn_context, true)?)
            }
        }
    }

    pub fn is_safe_prime(&self, ctx: Option<&mut BigNumberContext>) -> ClResult<bool> {
        match ctx {
            Some(c) => {
                // according to https://eprint.iacr.org/2003/186.pdf
                // a safe prime is congruent to 2 mod 3

                // a safe prime satisfies (p-1)/2 is prime. Since a
                // prime is odd, We just need to divide by 2
                Ok(
                    self.modulus(&BigNumber::from_u32(3)?, Some(c))? == BigNumber::from_u32(2)?
                        && self.is_prime(Some(c))?
                        && self.rshift1()?.is_prime(Some(c))?,
                )
            }
            None => {
                let mut context = BigNumber::new_context()?;
                self.is_safe_prime(Some(&mut context))
            }
        }
    }

    pub fn rand(size: usize) -> ClResult<BigNumber> {
        let mut bn = BigNumber::new()?;
        BigNumRef::rand(
            &mut bn.openssl_bn,
            size as i32,
            MsbOption::MAYBE_ZERO,
            false,
        )?;
        Ok(bn)
    }

    pub fn rand_range(&self) -> ClResult<BigNumber> {
        let mut bn = BigNumber::new()?;
        BigNumRef::rand_range(&self.openssl_bn, &mut bn.openssl_bn)?;
        Ok(bn)
    }

    pub fn num_bits(&self) -> ClResult<i32> {
        Ok(self.openssl_bn.num_bits())
    }

    pub fn is_bit_set(&self, n: i32) -> ClResult<bool> {
        Ok(self.openssl_bn.is_bit_set(n))
    }

    pub fn set_bit(&mut self, n: i32) -> ClResult<&mut BigNumber> {
        BigNumRef::set_bit(&mut self.openssl_bn, n)?;
        Ok(self)
    }

    pub fn from_u32(n: usize) -> ClResult<BigNumber> {
        let bn = BigNum::from_u32(n as u32)?;
        Ok(BigNumber { openssl_bn: bn })
    }

    pub fn from_dec(dec: &str) -> ClResult<BigNumber> {
        let bn = BigNum::from_dec_str(dec)?;
        Ok(BigNumber { openssl_bn: bn })
    }

    pub fn from_hex(hex: &str) -> ClResult<BigNumber> {
        let bn = BigNum::from_hex_str(hex)?;
        Ok(BigNumber { openssl_bn: bn })
    }

    pub fn from_bytes(bytes: &[u8]) -> ClResult<BigNumber> {
        let bn = BigNum::from_slice(bytes)?;
        Ok(BigNumber { openssl_bn: bn })
    }

    pub fn to_dec(&self) -> ClResult<String> {
        let result = self.openssl_bn.to_dec_str()?;
        Ok(result.to_string())
    }

    pub fn to_hex(&self) -> ClResult<String> {
        let result = self.openssl_bn.to_hex_str()?;
        Ok(result.to_string())
    }

    pub fn to_bytes(&self) -> ClResult<Vec<u8>> {
        Ok(self.openssl_bn.to_vec())
    }

    pub fn add(&self, a: &BigNumber) -> ClResult<BigNumber> {
        let mut bn = BigNumber::new()?;
        BigNumRef::checked_add(&mut bn.openssl_bn, &self.openssl_bn, &a.openssl_bn)?;
        Ok(bn)
    }

    pub fn sub(&self, a: &BigNumber) -> ClResult<BigNumber> {
        let mut bn = BigNumber::new()?;
        BigNumRef::checked_sub(&mut bn.openssl_bn, &self.openssl_bn, &a.openssl_bn)?;
        Ok(bn)
    }

    // TODO: There should be a mod_sqr using underlying math library's square modulo since squaring is faster.
    pub fn sqr(&self, ctx: Option<&mut BigNumberContext>) -> ClResult<BigNumber> {
        let mut bn = BigNumber::new()?;
        match ctx {
            Some(context) => BigNumRef::sqr(
                &mut bn.openssl_bn,
                &self.openssl_bn,
                &mut context.openssl_bn_context,
            )?,
            None => {
                let mut ctx = BigNumber::new_context()?;
                BigNumRef::sqr(
                    &mut bn.openssl_bn,
                    &self.openssl_bn,
                    &mut ctx.openssl_bn_context,
                )?;
            }
        }
        Ok(bn)
    }

    pub fn mul(&self, a: &BigNumber, ctx: Option<&mut BigNumberContext>) -> ClResult<BigNumber> {
        let mut bn = BigNumber::new()?;
        match ctx {
            Some(context) => BigNumRef::checked_mul(
                &mut bn.openssl_bn,
                &self.openssl_bn,
                &a.openssl_bn,
                &mut context.openssl_bn_context,
            )?,
            None => {
                let mut ctx = BigNumber::new_context()?;
                BigNumRef::checked_mul(
                    &mut bn.openssl_bn,
                    &self.openssl_bn,
                    &a.openssl_bn,
                    &mut ctx.openssl_bn_context,
                )?;
            }
        }
        Ok(bn)
    }

    pub fn mod_mul(
        &self,
        a: &BigNumber,
        n: &BigNumber,
        ctx: Option<&mut BigNumberContext>,
    ) -> ClResult<BigNumber> {
        let mut bn = BigNumber::new()?;
        match ctx {
            Some(context) => BigNumRef::mod_mul(
                &mut bn.openssl_bn,
                &self.openssl_bn,
                &a.openssl_bn,
                &n.openssl_bn,
                &mut context.openssl_bn_context,
            )?,
            None => {
                let mut ctx = BigNumber::new_context()?;
                BigNumRef::mod_mul(
                    &mut bn.openssl_bn,
                    &self.openssl_bn,
                    &a.openssl_bn,
                    &n.openssl_bn,
                    &mut ctx.openssl_bn_context,
                )?;
            }
        }
        Ok(bn)
    }

    pub fn mod_sub(
        &self,
        a: &BigNumber,
        n: &BigNumber,
        ctx: Option<&mut BigNumberContext>,
    ) -> ClResult<BigNumber> {
        let mut bn = BigNumber::new()?;
        match ctx {
            Some(context) => BigNumRef::mod_sub(
                &mut bn.openssl_bn,
                &self.openssl_bn,
                &a.openssl_bn,
                &n.openssl_bn,
                &mut context.openssl_bn_context,
            )?,
            None => {
                let mut ctx = BigNumber::new_context()?;
                BigNumRef::mod_sub(
                    &mut bn.openssl_bn,
                    &self.openssl_bn,
                    &a.openssl_bn,
                    &n.openssl_bn,
                    &mut ctx.openssl_bn_context,
                )?;
            }
        }
        Ok(bn)
    }

    pub fn div(&self, a: &BigNumber, ctx: Option<&mut BigNumberContext>) -> ClResult<BigNumber> {
        let mut bn = BigNumber::new()?;
        match ctx {
            Some(context) => BigNumRef::checked_div(
                &mut bn.openssl_bn,
                &self.openssl_bn,
                &a.openssl_bn,
                &mut context.openssl_bn_context,
            )?,
            None => {
                let mut ctx = BigNumber::new_context()?;
                BigNumRef::checked_div(
                    &mut bn.openssl_bn,
                    &self.openssl_bn,
                    &a.openssl_bn,
                    &mut ctx.openssl_bn_context,
                )?;
            }
        }
        Ok(bn)
    }

    pub fn gcd(
        a: &BigNumber,
        b: &BigNumber,
        ctx: Option<&mut BigNumberContext>,
    ) -> ClResult<BigNumber> {
        let mut gcd = BigNumber::new()?;
        match ctx {
            Some(context) => BigNumRef::gcd(
                &mut gcd.openssl_bn,
                &a.openssl_bn,
                &b.openssl_bn,
                &mut context.openssl_bn_context,
            )?,
            None => {
                let mut ctx = BigNumber::new_context()?;
                BigNumRef::gcd(
                    &mut gcd.openssl_bn,
                    &a.openssl_bn,
                    &b.openssl_bn,
                    &mut ctx.openssl_bn_context,
                )?;
            }
        }
        Ok(gcd)
    }

    // Question: The *_word APIs seem odd. When the method is already mutating, why return the reference?

    pub fn add_word(&mut self, w: u32) -> ClResult<&mut BigNumber> {
        BigNumRef::add_word(&mut self.openssl_bn, w)?;
        Ok(self)
    }

    pub fn sub_word(&mut self, w: u32) -> ClResult<&mut BigNumber> {
        BigNumRef::sub_word(&mut self.openssl_bn, w)?;
        Ok(self)
    }

    pub fn mul_word(&mut self, w: u32) -> ClResult<&mut BigNumber> {
        BigNumRef::mul_word(&mut self.openssl_bn, w)?;
        Ok(self)
    }

    pub fn div_word(&mut self, w: u32) -> ClResult<&mut BigNumber> {
        BigNumRef::div_word(&mut self.openssl_bn, w)?;
        Ok(self)
    }

    pub fn mod_exp(
        &self,
        a: &BigNumber,
        b: &BigNumber,
        ctx: Option<&mut BigNumberContext>,
    ) -> ClResult<BigNumber> {
        match ctx {
            Some(context) => self._mod_exp(a, b, context),
            None => {
                let mut ctx = BigNumber::new_context()?;
                self._mod_exp(a, b, &mut ctx)
            }
        }
    }

    fn _mod_exp(
        &self,
        a: &BigNumber,
        b: &BigNumber,
        ctx: &mut BigNumberContext,
    ) -> ClResult<BigNumber> {
        let mut bn = BigNumber::new()?;

        if a.openssl_bn.is_negative() {
            BigNumRef::mod_exp(
                &mut bn.openssl_bn,
                &self.inverse(b, Some(ctx))?.openssl_bn,
                &a.set_negative(false)?.openssl_bn,
                &b.openssl_bn,
                &mut ctx.openssl_bn_context,
            )?;
        } else {
            BigNumRef::mod_exp(
                &mut bn.openssl_bn,
                &self.openssl_bn,
                &a.openssl_bn,
                &b.openssl_bn,
                &mut ctx.openssl_bn_context,
            )?;
        };
        Ok(bn)
    }

    pub fn modulus(
        &self,
        a: &BigNumber,
        ctx: Option<&mut BigNumberContext>,
    ) -> ClResult<BigNumber> {
        let mut bn = BigNumber::new()?;
        match ctx {
            Some(context) => BigNumRef::nnmod(
                &mut bn.openssl_bn,
                &self.openssl_bn,
                &a.openssl_bn,
                &mut context.openssl_bn_context,
            )?,
            None => {
                let mut ctx = BigNumber::new_context()?;
                BigNumRef::nnmod(
                    &mut bn.openssl_bn,
                    &self.openssl_bn,
                    &a.openssl_bn,
                    &mut ctx.openssl_bn_context,
                )?;
            }
        }
        Ok(bn)
    }

    pub fn exp(&self, a: &BigNumber, ctx: Option<&mut BigNumberContext>) -> ClResult<BigNumber> {
        let mut bn = BigNumber::new()?;
        match ctx {
            Some(context) => BigNumRef::exp(
                &mut bn.openssl_bn,
                &self.openssl_bn,
                &a.openssl_bn,
                &mut context.openssl_bn_context,
            )?,
            None => {
                let mut ctx = BigNumber::new_context()?;
                BigNumRef::exp(
                    &mut bn.openssl_bn,
                    &self.openssl_bn,
                    &a.openssl_bn,
                    &mut ctx.openssl_bn_context,
                )?;
            }
        }
        Ok(bn)
    }

    pub fn inverse(
        &self,
        n: &BigNumber,
        ctx: Option<&mut BigNumberContext>,
    ) -> ClResult<BigNumber> {
        let mut bn = BigNumber::new()?;
        match ctx {
            Some(context) => BigNumRef::mod_inverse(
                &mut bn.openssl_bn,
                &self.openssl_bn,
                &n.openssl_bn,
                &mut context.openssl_bn_context,
            )?,
            None => {
                let mut ctx = BigNumber::new_context()?;
                BigNumRef::mod_inverse(
                    &mut bn.openssl_bn,
                    &self.openssl_bn,
                    &n.openssl_bn,
                    &mut ctx.openssl_bn_context,
                )?;
            }
        }
        Ok(bn)
    }

    pub fn set_negative(&self, negative: bool) -> ClResult<BigNumber> {
        let mut bn = BigNum::from_slice(&self.openssl_bn.to_vec())?;
        bn.set_negative(negative);
        Ok(BigNumber { openssl_bn: bn })
    }

    pub fn is_negative(&self) -> bool {
        self.openssl_bn.is_negative()
    }

    pub fn increment(&self) -> ClResult<BigNumber> {
        let mut bn = BigNum::from_slice(&self.openssl_bn.to_vec())?;
        bn.add_word(1)?;
        Ok(BigNumber { openssl_bn: bn })
    }

    pub fn decrement(&self) -> ClResult<BigNumber> {
        let mut bn = BigNum::from_slice(&self.openssl_bn.to_vec())?;
        bn.sub_word(1)?;
        Ok(BigNumber { openssl_bn: bn })
    }

    pub fn lshift1(&self) -> ClResult<BigNumber> {
        let mut bn = BigNumber::new()?;
        BigNumRef::lshift1(&mut bn.openssl_bn, &self.openssl_bn)?;
        Ok(bn)
    }

    pub fn rshift1(&self) -> ClResult<BigNumber> {
        let mut bn = BigNumber::new()?;
        BigNumRef::rshift1(&mut bn.openssl_bn, &self.openssl_bn)?;
        Ok(bn)
    }

    pub fn rshift(&self, n: u32) -> ClResult<BigNumber> {
        let mut bn = BigNumber::new()?;
        BigNumRef::rshift(&mut bn.openssl_bn, &self.openssl_bn, n as i32)?;
        Ok(bn)
    }

    pub fn mod_div(
        &self,
        b: &BigNumber,
        p: &BigNumber,
        ctx: Option<&mut BigNumberContext>,
    ) -> ClResult<BigNumber> {
        //(a * (1/b mod p) mod p)
        match ctx {
            Some(context) => self._mod_div(b, p, context),
            None => {
                let mut context = BigNumber::new_context()?;
                self._mod_div(b, p, &mut context)
            }
        }
    }

    ///(a * (1/b mod p) mod p)
    fn _mod_div(
        &self,
        b: &BigNumber,
        p: &BigNumber,
        ctx: &mut BigNumberContext,
    ) -> ClResult<BigNumber> {
        let mut bn = BigNumber::new()?;
        BigNumRef::mod_mul(
            &mut bn.openssl_bn,
            &self.openssl_bn,
            &b.inverse(p, Some(ctx))?.openssl_bn,
            &p.openssl_bn,
            &mut ctx.openssl_bn_context,
        )?;
        Ok(bn)
    }

    pub fn random_qr(n: &BigNumber) -> ClResult<BigNumber> {
        let qr = n.rand_range()?.sqr(None)?.modulus(n, None)?;
        Ok(qr)
    }

    // Question: Why does this need to be a Result? When is creating a BigNumber same as another
    // BigNumber not possible given sufficient memory?
    pub fn try_clone(&self) -> ClResult<BigNumber> {
        let mut openssl_bn = BigNum::from_slice(&self.openssl_bn.to_vec()[..])?;
        openssl_bn.set_negative(self.is_negative());
        Ok(BigNumber { openssl_bn })
    }
}

impl Ord for BigNumber {
    fn cmp(&self, other: &BigNumber) -> Ordering {
        self.openssl_bn.cmp(&other.openssl_bn)
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
        self.openssl_bn == other.openssl_bn
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
                BigNumber::from_dec(value).map_err(E::custom)
            }
        }

        deserializer.deserialize_str(BigNumberVisitor)
    }
}

impl From<ErrorStack> for ClError {
    fn from(err: ErrorStack) -> Self {
        // TODO: FIXME: Analyze ErrorStack and split invalid structure errors from other errors
        err_msg!(InvalidState, "Internal OpenSSL error: {}", err)
    }
}

impl Default for BigNumber {
    fn default() -> BigNumber {
        BigNumber::from_u32(0).unwrap()
    }
}
