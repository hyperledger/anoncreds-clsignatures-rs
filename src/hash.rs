use sha2::{Digest, Sha256};

use crate::bn::BigNumber;
use crate::error::Result as ClResult;

#[derive(Debug, Copy, Clone, Default)]
pub enum ByteOrder {
    #[default]
    Big,
    Little,
}

pub fn hash_list_to_bignum(nums: &[Vec<u8>]) -> ClResult<BigNumber> {
    trace!("Helpers::hash_list_to_bignum: >>> nums: {:?}", nums);

    let mut hasher = Sha256::new();
    for num in nums.iter() {
        hasher.update(num);
    }
    let hash_bytes = hasher.finalize();
    let hash_num = BigNumber::from_bytes(&hash_bytes);

    trace!("Helpers::hash_list_to_bignum: <<< hash: {:?}", hash_num);

    hash_num
}

pub fn hash_to_bignum(input: &[u8], byte_order: ByteOrder) -> ClResult<BigNumber> {
    trace!("Helpers::hash_to_bignum: >>> input: {:?}", input);

    let mut hash_bytes = Sha256::digest(input);
    if matches!(byte_order, ByteOrder::Little) {
        hash_bytes.reverse();
    }
    let hash_num = BigNumber::from_bytes(&hash_bytes);

    trace!("Helpers::hash_to_bignum: <<< hash: {:?}", hash_num);

    hash_num
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_hash_as_int_works() {
        let nums = vec![
            BigNumber::from_hex("ff9d2eedfee9cffd9ef6dbffedff3fcbef4caecb9bffe79bfa94d3fdf6abfbff")
                .unwrap()
                .to_bytes()
                .unwrap(),
            BigNumber::from_hex("ff9d2eedfee9cffd9ef6dbffedff3fcbef4caecb9bffe79bfa9168615ccbc546")
                .unwrap()
                .to_bytes()
                .unwrap(),
        ];
        let res = hash_list_to_bignum(&nums);

        assert!(res.is_ok());
        assert_eq!(
            "2C2566C22E04AB3F18B3BA693823175002F10F400811363D26BBB33633AC8BAD",
            res.unwrap().to_hex().unwrap()
        );
    }
}
