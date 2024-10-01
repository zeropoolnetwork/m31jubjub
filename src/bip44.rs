use core::str::FromStr;
use alloc::vec::Vec;
use alloc::string::String;
use alloc::borrow::ToOwned;

use crate::eddsa::SigParams;
use crate::{bip32, bip39};
use crate::m31::{/*FqBase,*/ Fs, M31JubJubSigParams};

pub struct HDWallet<Priv: bip32::PrivateKeyTrait, Pub: bip32::PublicKeyTrait> {
    pub master_key: bip32::ExtendedKey<Priv, Pub>,
    pub mnemonic_v: Vec<&'static str>,
    pub coin_type: u32,
    pub account: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DerivePath {
    pub is_priv: bool,
    pub nums: Vec<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DerivePathError {
    Prefix,
    TooShort,
    EmptyChildNum(usize),
    U32Parsing(usize),
    HardenedAfterNot(usize),
//    ToBigChildNum(usize),
    Failed,
    EncodingFailed,
    PublicKeyFailed,
    PrivateFromPublic,
}

impl FromStr for DerivePath {
    type Err = DerivePathError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let path: Vec<&str> = s.split('/').collect();
        if path.len() < 2 {
            return Err(Self::Err::TooShort);
        }
        let is_priv = match path[0] {
            "m" => {
                true
            },
            "M" => {
                false
            },
            _ => {
                return Err(Self::Err::Prefix);
            }
        };
        let nums_res: Result<Vec<u32>, Self::Err> = path.iter().skip(1).enumerate().map(|(i, subs)|  {
            if subs.len() == 0 {
                return Err(DerivePathError::EmptyChildNum(i));
            }
            let child_num = match &subs[(subs.len() -1)..subs.len()] {
                "\'" => subs[..(subs.len()-1)].parse().map(|x: u32| x | (1<<31)),
                _ => subs.parse(),
            };
            child_num.map_err(|_| DerivePathError::U32Parsing(i))
        }).collect();
        let nums = nums_res?;
        let mut hardened_flag = true;
        for (i, num) in nums.iter().enumerate() {
            if num >> 31 == 0 {
                hardened_flag = false;
            } else if !hardened_flag {
                return Err(Self::Err::HardenedAfterNot(i));
            }
        }
        Ok(Self {
            is_priv,
            nums,
        })
    }
}

impl HDWallet<Fs, bip32::PublicKeyType> {
    pub fn new(mnemonic_v: &[&'static str], coin_type: u32, account: u32) -> Option<Self> {
        let bytes = bip39::mnemonic_to_bytes_validate(mnemonic_v).unwrap();
        let seed = bip39::bytes_to_seed(&bytes, "");
        let master_key = bip39::seed_to_extended_key(&seed)?;
        if coin_type >> 31 == 0 || account >> 31 == 0 {
            return None;
        }
        Some(Self {
            master_key,
            mnemonic_v: mnemonic_v.to_owned(),
            coin_type,
            account,
        })
    }
}

impl HDWallet<Fs, bip32::PublicKeyType> {
    pub fn derive(&self, path: &str) -> Result<String, DerivePathError> {
        let d_path: DerivePath = path.parse()?;
        if d_path.is_priv && !self.master_key.key.is_priv() {
            return Err(DerivePathError::PrivateFromPublic);
        }
        let mut it = d_path.nums.iter();
        let Some(&child_num) = it.next() else {
            return Err(DerivePathError::TooShort);
        };
        #[cfg(test)]
        libc_print::std_name::println!("HDWallet::derive: child_num {}", child_num);
        let mut child_key = self.master_key.derive_child(child_num).ok_or(DerivePathError::Failed)?;
        for &child_num in it {
            #[cfg(test)]
            libc_print::std_name::println!("HDWallet::derive: child_num: {}", child_num);
            child_key = child_key.derive_child(child_num).ok_or(DerivePathError::Failed)?;
        }
        #[cfg(test)]
        libc_print::std_name::println!("HDWallet::derive: {:?}", child_key);
        #[cfg(test)]
        libc_print::std_name::println!("-------- done --------");
        if d_path.is_priv == self.master_key.key.is_priv() {
            child_key.encode().ok_or(DerivePathError::EncodingFailed)
        } else {
            child_key.get_pub()
                .map(|pck| pck.encode())
                .flatten()
                .ok_or(DerivePathError::EncodingFailed)
        }
    }
}

//impl HDWallet<Fs, bip32::PublicKeyType> {
//    pub fn derive(&self, path: &str) -> Result<String, DerivePathError> {
//        let d_path: DerivePath = path.parse()?;
//        if d_path.is_priv {
//            return Err(DerivePathError::PrivateFromPublic);
//        } else {
//            let sig_params = M31JubJubSigParams::default();
//            let mut ext_pub: bip32::ExtendedKey<_> = sig_params.public_key(self.master_key.key).try_into()
//                .map_err(|_| DerivePathError::PublicKeyFailed)?;
//            ext_pub.chain_code = self.master_key.chain_code;
//            for &child_num in &d_path.nums {
////                libc_print::std_name::println!("pubkey: child_num: {}", child_num);
//                ext_pub = ext_pub.derive_child(child_num).ok_or(DerivePathError::Failed)?;
//            }
//            ext_pub.encode().ok_or(DerivePathError::EncodingFailed)
//        }
//    }
//}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hdwallet_test_001_check_priv() {
        let (mnemonic_v, _priv_key) = bip39::generate_mnemonic();
        let hdw = HDWallet::new(&mnemonic_v[..], (1<<31) + 0, (1<<31) + 0).unwrap();
        let s_child_priv = hdw.derive("m/44'").unwrap();
        let child_priv: bip32::ExtendedKey<Fs, bip32::PublicKeyType> = s_child_priv.parse().unwrap();
//        let child_priv_manual = bip32::derive_priv(&hdw.master_key.key, &hdw.master_key.chain_code, (1<<31) + 44).unwrap();
        let child_priv_manual = bip32::derive_priv(hdw.master_key.key.private().unwrap(), &hdw.master_key.chain_code, (1<<31) + 44).unwrap();
        assert_eq!(child_priv_manual.0, *child_priv.key.private().unwrap());
    }

    #[test]
    fn hdwallet_test_001_check_pub() {
        let (mnemonic_v, _priv_key) = bip39::generate_mnemonic();
        let hdw = HDWallet::new(&mnemonic_v[..], (1<<31) + 0, (1<<31) + 0).unwrap();
        let s_child_pub = hdw.derive("M/44'").unwrap();
        let child_pub: bip32::ExtendedKey<Fs, bip32::PublicKeyType> = s_child_pub.parse().unwrap();

        let sig_params = M31JubJubSigParams::default();
        let master_pub = hdw.master_key.get_pub().unwrap();
//        let master_pub = sig_params.public_key(*hdw.master_key.key.private().unwrap());
        assert_eq!(sig_params.public_key(*hdw.master_key.key.private().unwrap()), *master_pub.key.public().unwrap());

        let child_priv_manual = bip32::derive_priv(hdw.master_key.key.private().unwrap(), &hdw.master_key.chain_code, (1<<31) + 44).unwrap();
        libc_print::std_name::println!("child_priv_manual: {:?}", child_priv_manual);

        let child_priv_manual_pub = sig_params.public_key(child_priv_manual.0);
        assert_eq!(child_priv_manual_pub, *child_pub.key.public().unwrap());

        // hardened key cannot be derived from public
        assert!(bip32::derive_pub(master_pub.key.public().unwrap(), &hdw.master_key.chain_code, (1<<31) + 44).is_none());

//        let child_pub_manual = bip32::derive_pub(master_pub.key.public().unwrap(), &hdw.master_key.chain_code, (1<<31) + 44).unwrap();
//        assert_eq!(child_pub_manual.0, *child_pub.key.public().unwrap());
    }

    #[test]
    fn hdwallet_test_002() {
        let (mnemonic_v, _priv_key) = bip39::generate_mnemonic();
        let hdw = HDWallet::new(&mnemonic_v[..], (1<<31) + 0, (1<<31) + 0).unwrap();
        let s_child_priv = hdw.derive("m/44'").unwrap();
        let s_child_pub = hdw.derive("M/44'").unwrap();
        libc_print::std_name::println!("{}", s_child_priv);
        libc_print::std_name::println!("{}", s_child_pub);

        let sig_params = M31JubJubSigParams::default();
        let child_priv: bip32::ExtendedKey<Fs, bip32::PublicKeyType> = s_child_priv.parse().unwrap();
        let child_priv_pub = sig_params.public_key(*child_priv.key.private().unwrap());
        let child_pub: bip32::ExtendedKey<Fs, bip32::PublicKeyType> = s_child_pub.parse().unwrap();
        assert_eq!(child_priv_pub, *child_pub.key.public().unwrap());
    }

    #[test]
    fn derive_path_test_001() {
        let dp0 = DerivePath::from_str("m/44444444444444444'");
        libc_print::std_name::println!("{:?}", dp0);
        assert!(dp0.is_err());
        
        let dp1 = DerivePath::from_str("m/44a'");
        libc_print::std_name::println!("{:?}", dp1);
        assert!(dp1.is_err());

        let dp2 = DerivePath::from_str("m/44h'"); // TODO: h suffix for hex
        libc_print::std_name::println!("{:?}", dp2);
        assert!(dp2.is_err());

        let dp3 = DerivePath::from_str("");
        libc_print::std_name::println!("{:?}", dp3);
        assert!(dp3.is_err());

        let dp4 = DerivePath::from_str("m/");
        libc_print::std_name::println!("{:?}", dp4);
        assert!(dp4.is_err());
    }
}
