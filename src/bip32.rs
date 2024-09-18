use core::error::Error;
use alloc::vec::Vec;

use crate::m31::{FqBase, Fs, M31JubJubSigParams};
use crate::eddsa::SigParams;
use rand::{thread_rng, Rng};
use zerocopy::AsBytes;

use ark_serialize::{CanonicalSerialize, CanonicalDeserialize, Compress, Validate};
use sha2::Sha512;
use hmac::{Hmac, Mac};

pub struct ChildNum {
    num: u32,
    is_hardened: bool,
}

pub const MASTER_SEED: &[u8;13] = b"Zeropool seed";

pub fn derive_hardened_priv(key: &Fs, chain_code: &[u8], num: u32) -> Option<(Fs, [u8; 32])> {
//    let mut buf: [u8; 32] = [0u8; 32];
//    let mut buf2: [u8; 32] = [0u8; 32];
//    let x = key.serialize_compressed(&mut buf[..]).ok()?;
//    let y = key.serialize_uncompressed(&mut buf2[..]).ok()?;
//    assert_eq!(buf, buf2);

    let mut source: [u8; 1 + 32 + 4] = [0u8; 37];
    key.serialize_compressed(&mut source[1..33]).unwrap();//.ok()?;
    let c_num_arr = num.to_be_bytes();
    source[33..].copy_from_slice(&c_num_arr);
    let mut hmac_obj = Hmac::<Sha512>::new_from_slice(chain_code).unwrap();//.ok()?;
    hmac_obj.update(&source);
    let hmac_res = hmac_obj.finalize();
    let mut hmac_res_v: [u8; 64] = [0u8; 64];
    hmac_res_v.copy_from_slice(hmac_res.into_bytes().as_slice());
    libc_print::std_name::println!("hmac_res_v: {:#?}", hmac_res_v);
    let new_key = Fs::deserialize_with_mode(&hmac_res_v[0..31], Compress::No, Validate::Yes).unwrap();//.ok()?; // TODO: one extra byte !!!!!!
    let mut new_chain_code: [u8; 32] = [0u8; 32];
    new_chain_code.copy_from_slice(&hmac_res_v[32..64]);
    Some((new_key, new_chain_code))
}


//trait BIP32Pub {
//    type PubKey;
//    fn derive_pub(&self, ChildNum) -> Self::PubKey;
//}
//
//trait BIP32Priv {
//    fn derive_priv(&self, ChildNum) -> Self;
//}

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
        assert!(derive_hardened_priv(&private_key, MASTER_SEED, 0).is_some());

//        let pka: Vec<u64> = private_key.iter().collect();
//        let private_key_arr: [u64; 4] = private_key.0.0;
    }
}
