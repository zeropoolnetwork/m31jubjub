use core::str::FromStr;
use alloc::string::String;
use alloc::borrow::ToOwned;
use alloc::vec::Vec;

use crate::eddsa::SigParams;
use crate::m31::{/*FqBase,*/ Fs, M31JubJubSigParams};
use super::{PrivateKeyTrait, PublicKeyTrait};
use super::key_types::KeyTypes;

use sha2::{Sha256, Digest};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize, Compress, Validate};
use base58::{ToBase58, FromBase58};
use ripemd::Ripemd160;

use super::{To33Bytes, To33BytesOblique, PRIV_SIZE, PUB_SIZE, PUB_PRIV_UNION_SIZE, EXTENDED_KEY_SIZE, EXTENDED_KEY_SIZE_WITHOUT_CHECKSUM, EXTENDED_KEY_CHECKSUM_SIZE};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ExtendedKey<Priv, Pub>
where
    Priv: PrivateKeyTrait,
    Pub: PublicKeyTrait,
{
    pub network_id: u32,
    pub depth: u8,
    pub fingerprint: [u8; 4],
    pub child_num: u32,
    pub chain_code: [u8; 32],
    pub key: KeyTypes<Priv, Pub>,
}

impl<Priv, Pub> ExtendedKey<Priv, Pub>
where
    Priv: PrivateKeyTrait<PublicType = Pub> + Sync + Send + 'static,
    Pub: PublicKeyTrait + Sync + Send + 'static,
{
    pub fn encode(&self) -> Option<String> {
        let mut arr: [u8; EXTENDED_KEY_SIZE] = [0u8; EXTENDED_KEY_SIZE];
        arr[..4].copy_from_slice(&self.network_id.to_be_bytes()[..]);
        arr[4] = self.depth;
        arr[5..9].copy_from_slice(&self.fingerprint[..]);
        arr[9..13].copy_from_slice(&self.child_num.to_be_bytes()[..]);
        arr[13..45].copy_from_slice(&self.chain_code[..]);
        self.key.to_33_bytes(&mut arr[45..EXTENDED_KEY_SIZE_WITHOUT_CHECKSUM])?;
        let mut hasher = Sha256::new();
        hasher.update(&arr[0..(EXTENDED_KEY_SIZE_WITHOUT_CHECKSUM)]);
        let res_0: [u8; 32] = hasher.finalize().into();
        let mut hasher = Sha256::new();
        hasher.update(&res_0[0..32]);
        let res_1: [u8; 32] = hasher.finalize().into();
        arr[EXTENDED_KEY_SIZE_WITHOUT_CHECKSUM..EXTENDED_KEY_SIZE].copy_from_slice(&res_1[..EXTENDED_KEY_CHECKSUM_SIZE]);
        let target = arr.to_base58();
        Some(target)
    }

    pub fn get_pub(&self) -> Option<Self> {
        if !self.key.is_priv() {
            return Some(self.clone());
        }
        let mut key_arr: [u8; PUB_PRIV_UNION_SIZE] = [0u8; PUB_PRIV_UNION_SIZE];
//        let priv_key = self.key.private().unwrap();
//        let sig_params  = M31JubJubSigParams::default();
        let pub_key = self.key.private().unwrap().get_public_key();//sig_params.public_key(priv_key.to_owned());
        pub_key.to_33_bytes(&mut key_arr)?;
//        bincode::serialize_into(&mut key_arr[..], &pub_key).ok()?;
        Some(Self {
            fingerprint: derive_fingerprint(&key_arr)?,
            network_id: Pub::NETWORK_ID_PUBLIC,
            depth: self.depth,
            chain_code: self.chain_code,
            child_num: self.child_num,
            key: KeyTypes::from_pub(pub_key),
        })
    }
}

impl<Priv, Pub> ExtendedKey<Priv, Pub>
where
    Priv: PrivateKeyTrait + CanonicalSerialize,
    Pub: PublicKeyTrait + serde::Serialize + core::fmt::Debug,
{
    pub fn derive_child(&self, num: u32) -> Option<Self> {
        #[cfg(test)]
        libc_print::std_name::println!("derive_child: self.key.is_priv(): {}", self.key.is_priv());
        if self.key.is_priv() {
            let (key, chain_code, child_num) = Priv::derive_priv(self.key.private()?, &self.chain_code, num)?;
            let mut key_arr: [u8; PRIV_SIZE] = [0u8; PRIV_SIZE];
            key.serialize_compressed(&mut key_arr[..]).ok()?;
            Some(Self {
                fingerprint: derive_fingerprint(&key_arr)?,
                key: KeyTypes::from_priv(key),
                chain_code,
                child_num,
                depth: self.depth +1,
//                is_priv: true,
                network_id: self.network_id,
            })
        } else {
            let (key, chain_code, child_num) = Pub::derive_pub(self.key.public()?, &self.chain_code, num)?;
            #[cfg(test)]
            libc_print::std_name::println!("Pub::derive_pub returned: {:?}", key);
            let mut key_arr: [u8; PUB_SIZE] = [0u8; PUB_SIZE];
            bincode::serialize_into(&mut key_arr[..], &key).ok()?;
            Some(Self {
                fingerprint: derive_fingerprint(&key_arr)?,
                key: KeyTypes::from_pub(key), 
                chain_code,
                child_num,
                depth: self.depth +1,
//                is_priv: false,
                network_id: Pub::NETWORK_ID_PUBLIC,
            })
        }
    }

    pub fn try_from_priv(key: Priv) -> Result<Self, ()> {
        let mut key_arr: [u8; PRIV_SIZE] = [0u8; PRIV_SIZE];
        key.serialize_compressed(&mut key_arr[..]).map_err(|_| ())?;
        let mut chain_code: [u8; 32] = [0u8; 32];
        const { assert!(super::MASTER_CHAIN_CODE.len() == 13); };
        chain_code[..13].copy_from_slice(&super::MASTER_CHAIN_CODE[..]);
        Ok(Self {
            fingerprint: derive_fingerprint(&key_arr).ok_or(())?,
            network_id: super::MAINNET_NETWORK_ID_PRIVATE,
            depth: 0,
            chain_code,
            child_num: 0,
            key: KeyTypes::from_priv(key),
        })
    }

    pub fn try_from_pub(key: Pub) -> Result<Self, ()> {
        let mut key_arr: [u8; PUB_SIZE] = [0u8; PUB_SIZE];
        bincode::serialize_into(&mut key_arr[..], &key).map_err(|_| ())?;
        let mut chain_code: [u8; 32] = [0u8; 32];
        const { assert!(super::MASTER_CHAIN_CODE.len() == 13); };
        chain_code[..13].copy_from_slice(&super::MASTER_CHAIN_CODE[..]);
        Ok(Self {
            fingerprint: derive_fingerprint(&key_arr).ok_or(())?,
            network_id: super::MAINNET_NETWORK_ID_PUBLIC,
            depth: 0,
            chain_code,
            child_num: 0,
            key: KeyTypes::from_pub(key),
        })
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

impl<Priv, Pub> FromStr for ExtendedKey<Priv, Pub>
where
    Priv: PrivateKeyTrait + CanonicalDeserialize,
    Pub: PublicKeyTrait + for<'a> serde::Deserialize<'a>
//    T: To33Bytes,
// supported only for types, not consts
//    T: To33Bytes<PADDING_LEN = <ExtendedKey<T> as ExtendedKeyConfig>::PADDING_LEN>,
//    ExtendedKey<T>: ExtendedKeyConfig<KeyType = T>,
// equality constrains are not yet supported
//    <T as To33Bytes>::PADDING_LEN = <ExtendedKey<T> as ExtendedKeyConfig>::PADDING_LEN
{
    type Err = ExtendedKeyFromStrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() < 4 {
            return Err(Self::Err::StringLength);
        }
        let is_priv = if &s[..4] == super::EXTENDED_PRIVATE_KEY_PREFIX {
            true
        } else if &s[..4] == super::EXTENDED_PUBLIC_KEY_PREFIX {
            false
        } else {
            return Err(Self::Err::Prefix);
        };
        let v: Vec<u8> = FromBase58::from_base58(&s[..]).map_err(|_| Self::Err::Base58Err)?;
        if v.len() != EXTENDED_KEY_SIZE {
//            libc_print::std_name::println!("decodedlen: {}", v.len());
            return Err(Self::Err::DecodedLength);
        }
        
        let mut hasher = Sha256::new();
        hasher.update(&v[0..EXTENDED_KEY_SIZE_WITHOUT_CHECKSUM]);
        let res_0: [u8; 32] = hasher.finalize().into();
        let mut hasher = Sha256::new();
        hasher.update(&res_0[0..32]);
        let res_1: [u8; 32] = hasher.finalize().into();
        if res_1[..4] != v[EXTENDED_KEY_SIZE_WITHOUT_CHECKSUM..EXTENDED_KEY_SIZE] {
            return Err(Self::Err::CheckSum);
        }

        let padding_len = if is_priv {
            Priv::PADDING_LEN
        } else {
            Pub::PADDING_LEN
        };
        if v[45..(45 + padding_len)].iter().any(|&b| b != 0x00) {
//            libc_print::std_name::println!("{:#?}", &v[45..(45 + Self::PADDING_LEN)]);
            return Err(Self::Err::KeyBytePadding);
        }

        let key = if is_priv {
            let bs = &v[45+padding_len..EXTENDED_KEY_SIZE_WITHOUT_CHECKSUM];
            KeyTypes::from_priv(Priv::deserialize_compressed(bs).map_err(|_| Self::Err::Key)?)
        } else {
            let bs = &v[45+padding_len..EXTENDED_KEY_SIZE_WITHOUT_CHECKSUM];
            KeyTypes::from_pub(bincode::deserialize(bs).map_err(|_| Self::Err::Key)?)
        };

        Ok(Self {
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
    use rand::{Rng, thread_rng};

    #[test]
    fn find_prefix() {
        let target_prefix = "Aprv";
//        let target_prefix = "Apub";

        let mut a = 0;
        let mut b = 0xffffffff;
        
        let private_key: Fs = thread_rng().gen();
        let mut ext = ExtendedKey::try_from_priv(private_key).unwrap();
  
        while a <= b {
            let t: u32 = ((a as u64 + b as u64)/2) as u32;
            libc_print::std_name::println!("t: {}", t);

            ext.network_id = t;

            let s = ext.encode().unwrap();

            #[cfg(test)]
            libc_print::std_name::println!("s: {}", s);
            if s.starts_with(target_prefix) {
                #[cfg(test)]
                libc_print::std_name::println!("network_id: {}\ns: {}", t, s);
//                    return Some(target);
                break;
            }
            match s.as_str().cmp(target_prefix) {
                core::cmp::Ordering::Less => a = t +1,
                core::cmp::Ordering::Greater => b = t -1,
                core::cmp::Ordering::Equal => panic!("WTF?????????????"),
            }
        }
    }
}

