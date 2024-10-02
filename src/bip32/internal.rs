use crate::m31::{/*FqBase,*/ Fs, M31JubJubSigParams};
use crate::curve::{Params, Point, PointProjective};
use crate::eddsa::SigParams;

use ark_serialize::{CanonicalSerialize, CanonicalDeserialize, Compress, Validate};

use sha2::{Sha256, Sha512, Digest};
use hmac::{Hmac, Mac};

use super::{PublicKeyType, To33Bytes, PUB_PRIV_UNION_SIZE, PRIV_SIZE, PUB_SIZE};

pub fn derive_priv(private_key: &Fs, chain_code: &[u8], num: u32) -> Option<(Fs, [u8; 32], u32)> {
    #[cfg(test)]
    libc_print::std_name::println!("derive_priv");
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
        let mut ser: [u8; PUB_PRIV_UNION_SIZE] = [0u8; PUB_PRIV_UNION_SIZE];
        public_key.to_33_bytes(&mut ser)?;
//        bincode::serialize_into(&mut ser[1..], &public_key).unwrap();
//        libc_print::std_name::println!("{:#?}", ser);
//        public_key.serialize_compressed(&mut ser[..]).unwrap();
        hmac_obj.update(&ser);
    } else {
        let mut source: [u8; PUB_PRIV_UNION_SIZE] = [0u8; PUB_PRIV_UNION_SIZE];
        private_key.to_33_bytes(&mut source)?;
//        assert_eq!(private_key.serialized_size(Compress::Yes), 31);
//        private_key.serialize_compressed(&mut source[2..33]).unwrap();
        hmac_obj.update(&source);
    }
    let num_be = num.to_be_bytes();
    hmac_obj.update(&num_be);
    let hmac_res = hmac_obj.finalize();
    hmac_res_v.copy_from_slice(hmac_res.into_bytes().as_slice());

    if let Ok(tweak) = Fs::deserialize_with_mode(&hmac_res_v[..PRIV_SIZE], Compress::Yes, Validate::Yes) {// TODO: one extra byte !!!!!!
        #[cfg(test)]
        libc_print::std_name::println!("tweak: {:#?}", tweak);
        let new_key = tweak + private_key;
        let mut new_chain_code: [u8; 32] = [0u8; 32];
        new_chain_code.copy_from_slice(&hmac_res_v[32..64]);
        Some((new_key, new_chain_code, num))
    } else {
//        libc_print::std_name::println!("+1");
        derive_priv(private_key, chain_code, num+1)
    }
}

pub fn derive_pub_unchecked(pub_key: &PublicKeyType, chain_code: &[u8], num: u32) -> Option<(PublicKeyType, [u8; 32], u32)> {
    #[cfg(test)]
    libc_print::std_name::println!("derive_pub_unchecked: num == {}", num);
    let mut hmac_obj = Hmac::<Sha512>::new_from_slice(chain_code).unwrap();//.ok()?;
    let mut hmac_res_v: [u8; 64] = [0u8; 64];

    let mut ser: [u8; PUB_PRIV_UNION_SIZE] = [0u8; PUB_PRIV_UNION_SIZE];
    pub_key.to_33_bytes(&mut ser)?;
//    bincode::serialize_into(&mut ser[1..], &pub_key).unwrap();
//        libc_print::std_name::println!("{:#?}", ser);
//        public_key.serialize_compressed(&mut ser[..]).unwrap();
    hmac_obj.update(&ser);
    let num_be = num.to_be_bytes();
    hmac_obj.update(&num_be);
    let hmac_res = hmac_obj.finalize();
    hmac_res_v.copy_from_slice(hmac_res.into_bytes().as_slice());

    if let Ok(tweak) = Fs::deserialize_with_mode(&hmac_res_v[0..PRIV_SIZE], Compress::Yes, Validate::Yes) {// TODO: one extra byte !!!!!!
        #[cfg(test)]
        libc_print::std_name::println!("tweak: {:#?}", tweak);
//        let sig_params = M31JubJubSigParams::default();
//        let pub_key_point_tweak: PointProjective<_> = Point::<M31JubJubSigParams>::suibgroup_decompress(sig_params.public_key(tweak)).unwrap().into();//tweak + private_key;
        let pub_key_point_tweak: PointProjective<_> = <M31JubJubSigParams as SigParams::<8>>::P::G8*tweak;//tweak + private_key;
        let pub_key_point: PointProjective<_> = Point::subgroup_decompress(*pub_key)?.into();
        let new_pub_key_project = pub_key_point + pub_key_point_tweak;// + *pub_key;
        let new_pub_key: Point<_> = new_pub_key_project.into();
        let mut new_chain_code: [u8; 32] = [0u8; 32];
        new_chain_code.copy_from_slice(&hmac_res_v[32..64]);
        #[cfg(test)]
        libc_print::std_name::println!("OKAY");
        Some((new_pub_key.x, new_chain_code, num))
    } else {
        #[cfg(test)]
        libc_print::std_name::println!("+1");
        derive_pub_unchecked(pub_key, chain_code, num+1)
    }
}
