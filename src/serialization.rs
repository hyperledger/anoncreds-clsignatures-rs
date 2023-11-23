use crate::error::Result as ClResult;
use serde::de::{Error, SeqAccess, Visitor};
use serde_json::Value;
use std::fmt;
use serde::Deserializer;

#[macro_export]
macro_rules! serializable_crypto_primitive {
    ($type_:ident) => {
        #[cfg(feature = "serde")]
        impl Serialize for $type_ {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
                where
                    S: Serializer,
            {
                serialize_crypto_primitive(self, serializer)
            }
        }

        #[cfg(feature = "serde")]
        impl<'a> Deserialize<'a> for $type_ {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
                where
                    D: Deserializer<'a>,
            {
                deserialize_crypto_primitive(deserializer)
            }
        }
    };
}

pub(crate) trait SerializableCryptoPrimitive {
    fn name() -> &'static str;
    fn to_string(&self) -> ClResult<String>;
    fn to_bytes(&self) -> ClResult<Vec<u8>>;
    fn from_string(value: &str) -> ClResult<Self> where Self: Sized;
    fn from_bytes(value: &[u8]) -> ClResult<Self> where Self: Sized;
}

pub(crate) fn serialize_crypto_primitive<S, V>(value: &V, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer, V: SerializableCryptoPrimitive
{
    if serializer.is_human_readable() {
        serializer.serialize_newtype_struct(
            V::name(),
            &value.to_string().map_err(serde::ser::Error::custom)?,
        )
    } else {
        serializer.serialize_newtype_struct(
            V::name(),
            &value.to_bytes().map_err(serde::ser::Error::custom)?,
        )
    }
}

pub(crate) fn deserialize_crypto_primitive<'a, D, V>(deserializer: D) -> Result<V, D::Error>
    where
        D: Deserializer<'a>,
        V: SerializableCryptoPrimitive,
{
    deserializer.deserialize_any(CryptoPrimitiveVisitor(
        V::name(),
        V::from_string,
        V::from_bytes,
    ))
}

#[cfg(feature = "serde")]
#[derive(Debug)]
struct CryptoPrimitiveVisitor<FromString, FromBytes>(
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Serialize, Deserialize, Serializer};

    #[derive(Debug, PartialEq, Eq)]
    struct CryptoMock {
        value: String,
    }

    const MOCK_VALUE: &str = "1111";

    impl SerializableCryptoPrimitive for CryptoMock {
        fn name() -> &'static str {
            "CryptoMock"
        }

        fn to_string(&self) -> ClResult<String> {
            Ok("1111".to_string())
        }

        fn to_bytes(&self) -> ClResult<Vec<u8>> {
            Ok(vec![1, 1, 1, 1])
        }

        fn from_string(_value: &str) -> ClResult<Self> where Self: Sized {
            Ok(
                CryptoMock {
                    value: MOCK_VALUE.to_string(),
                }
            )
        }

        fn from_bytes(_value: &[u8]) -> ClResult<Self> where Self: Sized {
            Ok(
                CryptoMock {
                    value: MOCK_VALUE.to_string(),
                }
            )
        }
    }

    serializable_crypto_primitive!(CryptoMock);

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct Object {
        value: CryptoMock
    }

    #[test]
    fn crypto_primitive_serialization_deserialization_works() {
        let object = Object {
            value: CryptoMock { value: MOCK_VALUE.to_string() },
        };
        let json_serialized = serde_json::to_string(&object).unwrap();
        let expected_json = r#"{"value":"1111"}"#;
        assert_eq!(expected_json, json_serialized);

        let rmp_serialized = rmp_serde::to_vec(&object).unwrap();
        let expected_bytes: Vec<u8> = vec![145, 148, 1, 1, 1, 1];
        assert_eq!(expected_bytes, rmp_serialized);

        assert_ne!(json_serialized.as_bytes(), rmp_serialized);
        assert!(json_serialized.len() > rmp_serialized.len());

        let json_deserialized: Object = serde_json::from_str(&json_serialized).unwrap();
        let rmp_deserialized: Object = rmp_serde::from_slice(&rmp_serialized).unwrap();
        assert_eq!(json_deserialized, rmp_deserialized);
    }
}
