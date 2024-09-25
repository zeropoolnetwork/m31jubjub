use core::str::FromStr;
use alloc::vec::Vec;
use alloc::string::String;
use alloc::borrow::ToOwned;

use crate::eddsa::SigParams;
use crate::{bip32, bip39};
use crate::m31::{/*FqBase,*/ Fs, M31JubJubSigParams};

pub struct HDWallet {
    pub master_key: bip32::ExtendedKey<Fs>,
    pub mnemonic_v: Vec<&'static str>,
    pub coin_type: u32,
    pub account: u32,
}

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

impl HDWallet {
    pub fn new(mnemonic_v: &[&'static str], coin_type: u32, account: u32) -> Option<Self> {
        let bytes = bip39::mnemonic_to_bytes_validate(mnemonic_v).unwrap();
        let seed = bip39::bytes_to_seed(&bytes, "");
        let master_key = bip39::seed_to_extended_key(&seed)?;
        Some(Self {
            master_key,
            mnemonic_v: mnemonic_v.to_owned(),
            coin_type,
            account,
        })
    }
    pub fn derive(&self, path: &str) -> Result<String, DerivePathError> {
        let d_path: DerivePath = path.parse()?;
        if d_path.is_priv {
            let mut it = d_path.nums.iter();
            let Some(&child_num) = it.next() else {
                return Err(DerivePathError::TooShort);
            };
            let mut ext_priv = self.master_key.derive_child(child_num).ok_or(DerivePathError::Failed)?;
            for &child_num in it {
                ext_priv = ext_priv.derive_child(child_num).ok_or(DerivePathError::Failed)?;
            }
            ext_priv.encode().ok_or(DerivePathError::EncodingFailed)
        } else {
            let sig_params = M31JubJubSigParams::default();
            let mut ext_pub: bip32::ExtendedKey<_> = sig_params.public_key(self.master_key.key).try_into()
                .map_err(|_| DerivePathError::PublicKeyFailed)?;
            for &child_num in &d_path.nums {
                ext_pub = ext_pub.derive_child(child_num).ok_or(DerivePathError::Failed)?;
            }
            ext_pub.encode().ok_or(DerivePathError::EncodingFailed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hdwallet_test_001() {
        let (mnemonic_v, _priv_key) = bip39::generate_mnemonic();
        let hdw = HDWallet::new(&mnemonic_v[..], 0, 0).unwrap();
        let child = hdw.derive("m/44'/0'/0'/0").unwrap();
        libc_print::std_name::println!("{}", child);
    }
}
