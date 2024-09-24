use core::str::FromStr;
use core::error::Error;
use alloc::vec::Vec;
use alloc::string::String;
use alloc::borrow::ToOwned;

use crate::m31::{FqBase, Fs, M31JubJubSigParams};
use crate::eddsa::SigParams;
use crate::curve::{Params, Point, PointProjective};
use rand::{thread_rng, Rng};
use serde::Serialize;
//use zerocopy::AsBytes;

use ark_serialize::{CanonicalSerialize, CanonicalDeserialize, Compress, Validate};
use sha2::{Sha256, Sha512, Digest};
use ripemd::Ripemd160;
use hmac::{Hmac, Mac};
use base58::{ToBase58, FromBase58};

use p3_field::extension::BinomialExtensionField;
use p3_mersenne_31::Mersenne31;

pub const MASTER_SEED: &[u8;13] = b"Zeropool seed";
pub const EXTENDED_PRIVATE_KEY_PREFIX: &'static str = "zprv";
pub const EXTENDED_PUBLIC_KEY_PREFIX: &'static str = "zpub";
pub const MAINNET_NETWORK_ID: u32 = 0x5a65506f; // ZePo

pub fn derive_priv(private_key: &Fs, chain_code: &[u8], num: u32) -> Option<(Fs, [u8; 32], u32)> {
//    let mut buf: [u8; 32] = [0u8; 32];
//    let mut buf2: [u8; 32] = [0u8; 32];
//    let x = key.serialize_compressed(&mut buf[..]).ok()?;
//    let y = key.serialize_uncompressed(&mut buf2[..]).ok()?;
//    assert_eq!(buf, buf2);

    let mut hmac_obj = Hmac::<Sha512>::new_from_slice(chain_code).unwrap();//.ok()?;
    let mut hmac_res_v: [u8; 64] = [0u8; 64];

    if (num >> 31) == 0 {
        let sig_params = M31JubJubSigParams::default();
        let public_key = sig_params.public_key(*private_key);
        let mut ser: [u8; 33] = [0u8; 33];
        bincode::serialize_into(&mut ser[1..], &public_key).unwrap();
//        libc_print::std_name::println!("{:#?}", ser);
//        public_key.serialize_compressed(&mut ser[..]).unwrap();
        hmac_obj.update(&ser);
    } else {
        let mut source: [u8; 33] = [0u8; 33];
        assert_eq!(private_key.serialized_size(Compress::Yes), 31);
        private_key.serialize_compressed(&mut source[1..32]).unwrap();
        hmac_obj.update(&source);
    }
    let num_be = num.to_be_bytes();
    hmac_obj.update(&num_be);
    let hmac_res = hmac_obj.finalize();
    hmac_res_v.copy_from_slice(hmac_res.into_bytes().as_slice());

    if let Ok(tweak) = Fs::deserialize_with_mode(&hmac_res_v[0..31], Compress::Yes, Validate::Yes) {// TODO: one extra byte !!!!!!
        libc_print::std_name::println!("tweak: {:#?}", tweak);
        let new_key = tweak + private_key;
        let mut new_chain_code: [u8; 32] = [0u8; 32];
        new_chain_code.copy_from_slice(&hmac_res_v[32..64]);
        Some((new_key, new_chain_code, num))
    } else {
        libc_print::std_name::println!("+1");
        derive_priv(private_key, chain_code, num+1)
    }
}

pub fn derive_pub(pub_key: &BinomialExtensionField<BinomialExtensionField<Mersenne31, 2>, 4>, chain_code: &[u8], num: u32) -> Option<(BinomialExtensionField<BinomialExtensionField<Mersenne31, 2>, 4>, [u8; 32], u32)> {
    if (num >> 31) != 0 {
        // hardened child
        return None;
    }

    let mut hmac_obj = Hmac::<Sha512>::new_from_slice(chain_code).unwrap();//.ok()?;
    let mut hmac_res_v: [u8; 64] = [0u8; 64];

    let mut ser: [u8; 33] = [0u8; 33];
    bincode::serialize_into(&mut ser[1..], &pub_key).unwrap();
//        libc_print::std_name::println!("{:#?}", ser);
//        public_key.serialize_compressed(&mut ser[..]).unwrap();
    hmac_obj.update(&ser);
    let num_be = num.to_be_bytes();
    hmac_obj.update(&num_be);
    let hmac_res = hmac_obj.finalize();
    hmac_res_v.copy_from_slice(hmac_res.into_bytes().as_slice());

    if let Ok(tweak) = Fs::deserialize_with_mode(&hmac_res_v[0..31], Compress::Yes, Validate::Yes) {// TODO: one extra byte !!!!!!
        libc_print::std_name::println!("tweak: {:#?}", tweak);
//        let sig_params = M31JubJubSigParams::default();
//        let pub_key_point_tweak: PointProjective<_> = Point::<M31JubJubSigParams>::suibgroup_decompress(sig_params.public_key(tweak)).unwrap().into();//tweak + private_key;
        let pub_key_point_tweak: PointProjective<_> = <M31JubJubSigParams as SigParams::<8>>::P::G8*tweak;//tweak + private_key;
        let pub_key_point: PointProjective<_> = Point::subgroup_decompress(*pub_key).unwrap().into();
        let new_pub_key_project = pub_key_point + pub_key_point_tweak;// + *pub_key;
        let new_pub_key: Point<_> = new_pub_key_project.into();
        let mut new_chain_code: [u8; 32] = [0u8; 32];
        new_chain_code.copy_from_slice(&hmac_res_v[32..64]);
        Some((new_pub_key.x, new_chain_code, num))
    } else {
        libc_print::std_name::println!("+1");
        derive_pub(pub_key, chain_code, num+1)
    }
}

pub trait To33Bytes {
    const PADDING_LEN: usize;
    #[must_use]
    fn to_33_bytes(&self, target: &mut [u8]) -> Option<()>;
}

impl To33Bytes for Fs {
    const PADDING_LEN: usize = 2;
    #[must_use]
    fn to_33_bytes(&self, target: &mut [u8]) -> Option<()> {
        if target.len() != 33 {
            return None;
        }
        self.serialize_compressed(&mut target[Self::PADDING_LEN..33]).ok()?;
        Some(())
    }
}

impl To33Bytes for BinomialExtensionField<BinomialExtensionField<Mersenne31, 2>, 4> {
    const PADDING_LEN: usize = 1;
    #[must_use]
    fn to_33_bytes(&self, target: &mut [u8]) -> Option<()> {
        if target.len() != 33 {
            return None;
        }
        bincode::serialize_into(&mut target[Self::PADDING_LEN..33], self).ok()?;
        Some(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ExtendedKey<T: To33Bytes> {
    pub is_priv: bool,
    pub network_id: u32,
    pub depth: u8,
    pub fingerprint: [u8; 4],
    pub child_num: u32,
    pub chain_code: [u8; 32],
    pub key: T,
}

impl<T: To33Bytes> ExtendedKey<T> {
    pub fn encode(&self) -> Option<String> {
        let mut arr: [u8;82] = [0u8; 82];
        arr[..4].copy_from_slice(&self.network_id.to_be_bytes()[..]);
        arr[4] = self.depth;
        arr[5..9].copy_from_slice(&self.fingerprint[..]);
        arr[9..13].copy_from_slice(&self.child_num.to_be_bytes()[..]);
        arr[13..45].copy_from_slice(&self.chain_code[..]);
        self.key.to_33_bytes(&mut arr[45..78])?;
        let mut hasher = Sha256::new();
        hasher.update(&arr[0..78]);
        let res_0: [u8; 32] = hasher.finalize().into();
        let mut hasher = Sha256::new();
        hasher.update(&res_0[0..32]);
        let res_1: [u8; 32] = hasher.finalize().into();
        arr[78..82].copy_from_slice(&res_1[..4]);
        let target = if self.is_priv {
            EXTENDED_PRIVATE_KEY_PREFIX.to_owned() + &arr.to_base58()
        } else {
            EXTENDED_PUBLIC_KEY_PREFIX.to_owned() + &arr.to_base58()
        };
        Some(target)
    }
}

#[derive(Clone, Copy, Debug)]
pub enum ExtendedKeyFromStrError {
    StringLength,
    Prefix,
    Base58Err,
    DecodedLength,
    CheckSum,
    NetworkId,
    ChildNum,
    KeyBytePadding,
    Key,
}

trait ExtendedKeyConfig {
    type KeyType;
    const PADDING_LEN: usize;
    const IS_PRIV: bool;
    
    fn from_bytes(bs: &[u8]) -> Option<Self::KeyType>;
}

impl ExtendedKeyConfig for ExtendedKey<Fs> {
    type KeyType = Fs;
    const PADDING_LEN: usize = 2;
    const IS_PRIV: bool = true;

    fn from_bytes(bs: &[u8]) -> Option<Self::KeyType> {
        Self::KeyType::deserialize_compressed(bs).ok()
    }
}

impl ExtendedKeyConfig for ExtendedKey<BinomialExtensionField<BinomialExtensionField<Mersenne31, 2>, 4>> {
    type KeyType = BinomialExtensionField<BinomialExtensionField<Mersenne31, 2>, 4>;
    const PADDING_LEN: usize = 1;
    const IS_PRIV: bool = false;

    fn from_bytes(bs: &[u8]) -> Option<Self::KeyType> {
        bincode::deserialize(bs).ok()
    }
}

impl<T> FromStr for ExtendedKey<T>
where
    T: To33Bytes,
// supported only for types, not consts
//    T: To33Bytes<PADDING_LEN = <ExtendedKey<T> as ExtendedKeyConfig>::PADDING_LEN>,
    ExtendedKey<T>: ExtendedKeyConfig<KeyType = T>,
// equality constrains are not yet supported
//    <T as To33Bytes>::PADDING_LEN = <ExtendedKey<T> as ExtendedKeyConfig>::PADDING_LEN
{
    type Err = ExtendedKeyFromStrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        assert_eq!(T::PADDING_LEN, Self::PADDING_LEN);
        if s.len() < 4 {
            return Err(Self::Err::StringLength);
        }
        match Self::IS_PRIV {
            true => {
                if &s[..4] != EXTENDED_PRIVATE_KEY_PREFIX {
                    return Err(Self::Err::Prefix);
                }
            },
            false => {
                if &s[..4] != EXTENDED_PUBLIC_KEY_PREFIX {
                    return Err(Self::Err::Prefix);
                }
            }
        }
        let v: Vec<u8> = FromBase58::from_base58(&s[4..]).map_err(|_| Self::Err::Base58Err)?;
        if v.len() != 82 {
            return Err(Self::Err::DecodedLength);
        }
        
        let mut hasher = Sha256::new();
        hasher.update(&v[0..78]);
        let res_0: [u8; 32] = hasher.finalize().into();
        let mut hasher = Sha256::new();
        hasher.update(&res_0[0..32]);
        let res_1: [u8; 32] = hasher.finalize().into();
        if res_1[..4] != v[78..82] {
            return Err(Self::Err::CheckSum);
        }

        if v[45..(45 + Self::PADDING_LEN)].iter().any(|&b| b != 0x00) {
            libc_print::std_name::println!("{:#?}", &v[45..(45 + Self::PADDING_LEN)]);
            return Err(Self::Err::KeyBytePadding);
        }

        let Some(key) = Self::from_bytes(&v[(45 + Self::PADDING_LEN)..]) else {
            return Err(Self::Err::Key);
        };

        Ok(Self {
            is_priv: Self::IS_PRIV,
            network_id: u32::from_be_bytes(v[0..4].try_into().map_err(|_| Self::Err::NetworkId)?),
            depth: v[4],
            fingerprint: {
                let mut arr: [u8; 4] = [0u8; 4];
                arr.copy_from_slice(&v[5..9]);
                arr
            },
            child_num: u32::from_be_bytes(v[9..13].try_into().map_err(|_| Self::Err::ChildNum)?),
            chain_code: {
                let mut arr: [u8; 32] = [0u8; 32];
                arr.copy_from_slice(&v[13..45]);
                arr
            },
            key,
        })
    }
}

pub fn derive_fingerprint(key: &[u8]) -> Option<[u8; 4]> {
    let mut hasher = Sha256::new();
    hasher.update(key);
    let res: [u8; 32] = hasher.finalize().into();
    let mut hasher2 = Ripemd160::new();
    hasher2.update(&res[..]);
    let res2: [u8; 20] = hasher2.finalize().into();
    let mut res3: [u8; 4] = [0u8; 4];
    res3.copy_from_slice(&res2[..4]);
    Some(res3)
}

#[cfg(test)]
mod tests {
    use super::*;

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

//        assert!(derive_priv(&private_key, MASTER_SEED, ChildNum{ num: 0, is_hardened: true }).is_some());
        assert!(derive_priv(&private_key, MASTER_SEED, 0).is_some());

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

        let child_priv = derive_priv(&private_key, MASTER_SEED, 0).unwrap();
        libc_print::std_name::println!("--------");
        let child_pub_0 = sig_params.public_key(child_priv.0);
        let child_pub_1 = derive_pub(&public_key, MASTER_SEED, 0).unwrap();
        
        assert_eq!(child_pub_1.2, child_priv.2);
        assert_eq!(child_pub_0, child_pub_1.0);
    }

    #[test]
    fn priv_test_002_extend_key_encode() {
//        let sig_params = M31JubJubSigParams::default();

        let private_key: Fs = thread_rng().gen();

        let mut private_key_arr: [u8; 32] = [0u8; 32];
        private_key.serialize_compressed(&mut private_key_arr[..32]).unwrap();

        let ext = ExtendedKey {
            is_priv: true,
            network_id: MAINNET_NETWORK_ID,
            depth: 0,
            fingerprint: derive_fingerprint(&private_key_arr).unwrap(),
            child_num: 0,
            chain_code: Default::default(),
            key: private_key,//: private_key_arr,
        };

        let encoded = ext.encode().unwrap();

        libc_print::std_name::println!("{}", encoded);
        
        let ext2: ExtendedKey<Fs> = encoded.parse().unwrap();

        assert_eq!(ext, ext2);
    }

    #[test]
    fn pub_test_002_extend_key_encode() {
        let sig_params = M31JubJubSigParams::default();

        let private_key: Fs = thread_rng().gen();
        let public_key: BinomialExtensionField<BinomialExtensionField<Mersenne31, 2>, 4> = sig_params.public_key(private_key);

        let mut private_key_arr: [u8; 32] = [0u8; 32];
        private_key.serialize_compressed(&mut private_key_arr[..32]).unwrap();

        let ext = ExtendedKey {
            is_priv: false,
            network_id: MAINNET_NETWORK_ID,
            depth: 0,
            fingerprint: derive_fingerprint(&private_key_arr).unwrap(),
            child_num: 0,
            chain_code: Default::default(),
            key: public_key,//: private_key_arr,
        };

        let encoded = ext.encode().unwrap();

        libc_print::std_name::println!("{}", encoded);
        
        let ext2: ExtendedKey<BinomialExtensionField<BinomialExtensionField<Mersenne31, 2>, 4>> = encoded.parse().unwrap();

        assert_eq!(ext, ext2);
    }
}
