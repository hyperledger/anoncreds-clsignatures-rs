use crate::error::Result as ClResult;
use serde::de::{Error, SeqAccess, Visitor};
use serde_json::Value;
use std::fmt;

#[cfg(feature = "serde")]
#[derive(Debug)]
pub(crate) struct CryptoPrimitiveVisitor<FromString, FromBytes>(
    pub &'static str,
    pub FromString,
    pub FromBytes,
);

#[cfg(feature = "serde")]
impl<'d, FromString, FromBytes, T> Visitor<'d> for CryptoPrimitiveVisitor<FromString, FromBytes>
where
    FromString: FnOnce(&str) -> ClResult<T>,
    FromBytes: FnOnce(&[u8]) -> ClResult<T>,
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

    fn visit_seq<V>(self, mut visitor: V) -> Result<Self::Value, V::Error>
    where
        V: SeqAccess<'d>,
    {
        let mut vec = Vec::new();

        while let Ok(Some(Value::Number(elem))) = visitor.next_element() {
            let num = elem
                .as_u64()
                .ok_or_else(|| V::Error::custom("Unexpected value"))?;
            vec.push(num as u8);
        }

        self.2(&vec).map_err(V::Error::custom)
    }
}
