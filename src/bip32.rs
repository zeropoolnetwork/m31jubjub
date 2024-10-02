use core::str::FromStr;
//use core::error::Error;
use alloc::vec::Vec;
use alloc::string::String;
//use alloc::borrow::ToOwned;

use crate::m31::{/*FqBase,*/ Fs, M31JubJubSigParams};
use crate::eddsa::SigParams;
use crate::curve::{Params, Point, PointProjective};
//use serde::Serialize;
//use zerocopy::AsBytes;

use ark_serialize::{CanonicalSerialize, CanonicalDeserialize, Compress, Validate};
use sha2::{Sha256, Sha512, Digest};
use ripemd::Ripemd160;
use hmac::{Hmac, Mac};
use base58::{ToBase58, FromBase58};

use p3_field::extension::BinomialExtensionField;
use p3_mersenne_31::Mersenne31;

mod internal;
mod extended_key;
mod key_types;


pub use extended_key::*;
pub use key_types::*;
pub use internal::*;

pub const MASTER_CHAIN_CODE: &[u8;13] = b"Zeropool seed";
pub const EXTENDED_PRIVATE_KEY_PREFIX: &'static str = "xprv"; //"zprv";
pub const EXTENDED_PUBLIC_KEY_PREFIX: &'static str = "xpub"; //"zpub";
pub const MAINNET_NETWORK_ID_PRIVATE: u32 = 0x0488ADE4; // 0x5a65506f; // ZePo
pub const MAINNET_NETWORK_ID_PUBLIC: u32 = 0x0488B21E; // 0x5a65506f; // ZePo

pub const PUB_PRIV_UNION_SIZE: usize = 33;
pub const PRIV_SIZE: usize = 31;
pub const PUB_SIZE: usize = 32;
pub const EXTENDED_KEY_SIZE: usize = 45 + PUB_PRIV_UNION_SIZE + EXTENDED_KEY_CHECKSUM_SIZE;
pub const EXTENDED_KEY_SIZE_WITHOUT_CHECKSUM: usize = EXTENDED_KEY_SIZE - EXTENDED_KEY_CHECKSUM_SIZE;
pub const EXTENDED_KEY_CHECKSUM_SIZE: usize = 4;

pub type PublicKeyType = BinomialExtensionField<BinomialExtensionField<Mersenne31, 2>, 4>;

pub trait PrivateKeyTrait: To33Bytes + Clone + Sized {
    type PublicType: PublicKeyTrait;
    const NETWORK_ID_PRIVATE: u32;
    fn derive_priv(&self, chain_code: &[u8], num: u32) -> Option<(Self, [u8; 32], u32)>;
    fn get_public_key(&self) -> Self::PublicType;
}

pub trait GetPrivateKey {
    type PrivateType: PublicKeyTrait;
    fn get_private_key(&self) -> impl core::borrow::Borrow<Self::PrivateType>;
}

pub trait DerivePrivate: GetPrivateKey {
    fn derive_priv(&self, chain_code: &[u8], num: u32) -> Option<(Self::PrivateType, [u8; 32], u32)>;
}

pub trait PublicKeyTrait: To33Bytes + Clone + Sized {
    const NETWORK_ID_PUBLIC: u32;
    fn derive_pub_unchecked(&self, chain_code: &[u8], num: u32) -> Option<(Self, [u8; 32], u32)>;
    fn derive_pub(&self, chain_code: &[u8], num: u32) -> Option<(Self, [u8; 32], u32)> {
        if (num>>31) != 0 {
            None
        } else {
            let (new_pub_key, new_chain_code, new_num) = Self::derive_pub_unchecked(self, chain_code, num)?;
            if (new_num >> 31) != 0 {
                None
            } else {
                Some((new_pub_key, new_chain_code, new_num))
            }
        }
    }
}

pub trait GetPublicKey {
    type PublicType: PublicKeyTrait;
    fn get_public_key(&self) -> impl core::borrow::Borrow<Self::PublicType>;
}

pub trait DerivePublic: GetPublicKey {
    fn derive_pub(&self, chain_code: &[u8], num: u32) -> Option<(Self::PublicType, [u8; 32], u32)>;
}



impl PrivateKeyTrait for Fs {
    type PublicType = PublicKeyType;
    const NETWORK_ID_PRIVATE: u32 = MAINNET_NETWORK_ID_PRIVATE;
    fn derive_priv(&self, chain_code: &[u8], num: u32) -> Option<(Self, [u8; 32], u32)> {
        internal::derive_priv(self, chain_code, num)
    }
    fn get_public_key(&self) -> Self::PublicType {
        let sig_params  = M31JubJubSigParams::default();
        sig_params.public_key(*self)
    }
}

impl PublicKeyTrait for PublicKeyType {
    const NETWORK_ID_PUBLIC: u32 = MAINNET_NETWORK_ID_PUBLIC;
    fn derive_pub_unchecked(&self, chain_code: &[u8], num: u32) -> Option<(Self, [u8; 32], u32)> {
        internal::derive_pub_unchecked(self, chain_code, num)
    }
}


pub fn derive_pub(pub_key: &PublicKeyType, chain_code: &[u8], num: u32) -> Option<(PublicKeyType, [u8; 32], u32)> {
    if (num >> 31) != 0 {
        // hardened child
        return None;
    }
    internal::derive_pub_unchecked(pub_key, chain_code, num)
}

pub trait To33Bytes {
    const PADDING_LEN: usize;
    #[must_use]
    fn to_33_bytes(&self, target: &mut [u8]) -> Option<()>;
}

impl To33Bytes for Fs {
    const PADDING_LEN: usize = PUB_PRIV_UNION_SIZE - PRIV_SIZE;
    #[must_use]
    fn to_33_bytes(&self, target: &mut [u8]) -> Option<()> {
        if target.len() != PUB_PRIV_UNION_SIZE {
            return None;
        }
        for i in 0..Self::PADDING_LEN {
            target[i] = 0x00;
        }
        self.serialize_compressed(&mut target[Self::PADDING_LEN..PUB_PRIV_UNION_SIZE]).ok()?;
        Some(())
    }
}

impl To33Bytes for PublicKeyType {
    const PADDING_LEN: usize = PUB_PRIV_UNION_SIZE - PUB_SIZE;
    #[must_use]
    fn to_33_bytes(&self, target: &mut [u8]) -> Option<()> {
        if target.len() != PUB_PRIV_UNION_SIZE {
            return None;
        }
        for i in 0..Self::PADDING_LEN {
            target[i] = 0x00;
        }
        bincode::serialize_into(&mut target[Self::PADDING_LEN..PUB_PRIV_UNION_SIZE], self).ok()?;
        Some(())
    }
}

pub trait To33BytesOblique {
    fn to_33_bytes(&self, target: &mut [u8]) -> Option<()>;
    fn padding(&self) -> usize;
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand::{thread_rng, Rng};

    #[test]
    fn priv_test_001() {
        let sig_params = M31JubJubSigParams::default();

        // generate private key
        let private_key: Fs = thread_rng().gen();

        // derive public key
        let public_key = sig_params.public_key(private_key);

        libc_print::std_name::println!("{:#?}", private_key);
        libc_print::std_name::println!("{:#?}", public_key);

        libc_print::std_name::println!("private_key.serialized_size(): {}", private_key.serialized_size(ark_serialize::Compress::No));

//        assert!(derive_priv(&private_key, MASTER_CHAIN_CODE, ChildNum{ num: 0, is_hardened: true }).is_some());
        assert!(internal::derive_priv(&private_key, MASTER_CHAIN_CODE, 0).is_some());

//        let pka: Vec<u64> = private_key.iter().collect();
//        let private_key_arr: [u64; 4] = private_key.0.0;
    }

    #[test]
    fn pub_test_001() {
        let sig_params = M31JubJubSigParams::default();

        let private_key: Fs = thread_rng().gen();

        let public_key = sig_params.public_key(private_key);

        libc_print::std_name::println!("{:#?}", private_key);
        libc_print::std_name::println!("{:#?}", public_key);

        let child_priv = internal::derive_priv(&private_key, MASTER_CHAIN_CODE, 0).unwrap();
        libc_print::std_name::println!("--------");
        let child_pub_0 = sig_params.public_key(child_priv.0);
        let child_pub_1 = derive_pub(&public_key, MASTER_CHAIN_CODE, 0).unwrap();
        
        assert_eq!(child_pub_1.2, child_priv.2);
        assert_eq!(child_pub_0, child_pub_1.0);
    }

    #[test]
    fn pub_test_001_hardened() {
        let sig_params = M31JubJubSigParams::default();

        let private_key: Fs = thread_rng().gen();

        let public_key = sig_params.public_key(private_key);

        libc_print::std_name::println!("{:#?}", private_key);
        libc_print::std_name::println!("{:#?}", public_key);

        let child_priv = internal::derive_priv(&private_key, MASTER_CHAIN_CODE, (1<<31) + 44).unwrap();
        libc_print::std_name::println!("--------");
        let child_pub_0 = sig_params.public_key(child_priv.0);

        assert!(derive_pub(&public_key, MASTER_CHAIN_CODE, (1<<31) + 44).is_none());
//        let child_pub_1 = derive_pub(&public_key, MASTER_CHAIN_CODE, (1<<31) + 44).unwrap();
//        
//        assert_eq!(child_pub_1.2, child_priv.2);
//        assert_eq!(child_pub_0, child_pub_1.0);
    }

    #[test]
    fn priv_test_002_extend_key_encode() {
//        let sig_params = M31JubJubSigParams::default();

        let private_key: Fs = thread_rng().gen();

        let mut private_key_arr: [u8; 32] = [0u8; 32];
        private_key.serialize_compressed(&mut private_key_arr[..32]).unwrap();

        let ext = ExtendedKey {
            network_id: MAINNET_NETWORK_ID_PRIVATE,
            depth: 0,
            fingerprint: extended_key::derive_fingerprint(&private_key_arr).unwrap(),
            child_num: 0,
            chain_code: Default::default(),
            key: KeyTypes::from_priv(private_key),//: private_key_arr,
        };

        let encoded = ext.encode().unwrap();

        libc_print::std_name::println!("{}", encoded);
        
        let ext2: ExtendedKey<Fs, PublicKeyType> = encoded.parse().unwrap();

        assert_eq!(ext, ext2);
    }

    #[test]
    fn pub_test_002_extend_key_encode() {
        let sig_params = M31JubJubSigParams::default();

        let private_key: Fs = thread_rng().gen();
        let public_key: PublicKeyType = sig_params.public_key(private_key);

        let mut private_key_arr: [u8; 32] = [0u8; 32];
        private_key.serialize_compressed(&mut private_key_arr[..32]).unwrap();

        let ext = ExtendedKey {
            network_id: MAINNET_NETWORK_ID_PUBLIC,
            depth: 0,
            fingerprint: extended_key::derive_fingerprint(&private_key_arr).unwrap(),
            child_num: 0,
            chain_code: Default::default(),
            key: KeyTypes::from_pub(public_key),//: private_key_arr,
        };

        let encoded = ext.encode().unwrap();

        libc_print::std_name::println!("{}", encoded);
        
        let ext2: ExtendedKey<Fs, PublicKeyType> = encoded.parse().unwrap();

        assert_eq!(ext, ext2);
    }

    #[test]
    fn priv_test_003_extend_key_derive_child() {
        let private_key: Fs = thread_rng().gen();

        let ext: ExtendedKey<Fs, PublicKeyType> = ExtendedKey::try_from_priv(private_key).unwrap();//.try_into().unwrap();

        let child_0 = ext.derive_child(0).unwrap();
        let (child_priv, child_chain_code, child_num) = internal::derive_priv(&private_key, &MASTER_CHAIN_CODE[..], 0).unwrap();
        let child_1 = {
            let mut tmp: ExtendedKey<Fs, PublicKeyType> = ExtendedKey::try_from_priv(child_priv).unwrap();//.try_into().unwrap();
            tmp.chain_code = child_chain_code;
            tmp.child_num = child_num;
            tmp.depth = 1;
            tmp
        };

        assert_eq!(child_0, child_1);
    }

    #[test]
    fn pub_test_003_extend_key_derive_child() {
        let sig_params = M31JubJubSigParams::default();
        let private_key: Fs = thread_rng().gen();
        let public_key = sig_params.public_key(private_key);

        let ext: ExtendedKey<Fs, PublicKeyType> = ExtendedKey::try_from_pub(public_key).unwrap();

        let child_0 = ext.derive_child(0).unwrap();
        let (child_pub, child_chain_code, child_num) = derive_pub(&public_key, &MASTER_CHAIN_CODE[..], 0).unwrap();
        let child_1 = {
            let mut tmp = ExtendedKey::try_from_pub(child_pub).unwrap();
            tmp.chain_code = child_chain_code;
            tmp.child_num = child_num;
            tmp.depth = 1;
            tmp
        };

        assert_eq!(child_0, child_1);
    }

    #[test]
    fn pub_test_003_extend_key_derive_child_hardened() {
        let sig_params = M31JubJubSigParams::default();
        let private_key: Fs = thread_rng().gen();
        let public_key = sig_params.public_key(private_key);

        let ext: ExtendedKey<Fs, PublicKeyType> = ExtendedKey::try_from_pub(public_key).unwrap();

        // hardened child cannot be derived from public key
        assert!(ext.derive_child((1<<31) + 44).is_none());
    }

    #[test]
    fn pub_test_004_derive_pub() {
        let sig_params = M31JubJubSigParams::default();
        let private_key: Fs = thread_rng().gen();
        let public_key = sig_params.public_key(private_key);
        assert!(derive_pub(&public_key, &MASTER_CHAIN_CODE[..], 0).is_some());
        assert!(derive_pub(&public_key, &MASTER_CHAIN_CODE[..], 1<<31).is_none());
        assert!(internal::derive_pub_unchecked(&public_key, &MASTER_CHAIN_CODE[..], 1<<31).is_some());
    }
}
