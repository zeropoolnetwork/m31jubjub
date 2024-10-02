use alloc::vec::Vec;

use crate::curve::{Params, Point, PointProjective};
use p3_symmetric::CryptographicHasher;
use p3_field::{Field, PrimeField32};
use ark_ff::{BigInteger, PrimeField};

use num_bigint::BigUint;
use core::iter::successors;
use sha3::{Digest, Keccak256};

use crate::flatten::ExtFieldFlattener;

pub trait SigParams<const HASHER_OUT: usize>: Clone {
    type P: Params;
    type HasherOut;
    type Fb: Field + PrimeField32;
    type Flattener: ExtFieldFlattener<<Self::P as Params>::Fq, Self::Fb>;

    type Hasher: CryptographicHasher<Self::Fb, [Self::Fb; HASHER_OUT]>;

    fn get_hasher(&self) -> &Self::Hasher;

    fn hash_message(&self, message: &[Self::Fb]) -> [Self::Fb; HASHER_OUT] {
        self.get_hasher().hash_slice(message)
    }

    fn public_key(&self, private_key: <Self::P as Params>::Fs) -> <Self::P as Params>::Fq {
        Point::from(Self::P::G8 * private_key).x
    }

    fn hash_r_a_m(
        &self,
        point_r: <Self::P as Params>::Fq,
        point_a: <Self::P as Params>::Fq,
        hashed_message: [Self::Fb; HASHER_OUT],
    ) -> <Self::P as Params>::Fs {
        let t = [point_r, point_a].iter()
            .flat_map(|e| Self::Flattener::flatten_iter(e)).copied()
            .chain(hashed_message.into_iter())
            .collect::<Vec<_>>();

        let num_limbs = (<Self::P as Params>::Fs::MODULUS_BIT_SIZE + 31) / 32;
        let hash = self.get_hasher().hash_slice(&t);
        let limbs = successors(Some(hash), |x| Some(self.get_hasher().hash_slice(x)))
            .flat_map(|x| x.into_iter())
            .map(|x| x.as_canonical_u32())
            .take(num_limbs as usize)
            .collect::<Vec<_>>();

        BigUint::from_slice(&limbs).into()
    }

    fn hash_secret_m(
        &self,
        secret: <Self::P as Params>::Fs,
        message: &[Self::Fb],
    ) -> <Self::P as Params>::Fs {
        let mut hasher = Keccak256::new();
        hasher.update(secret.into_bigint().to_bytes_le());
        for &item in message.iter() {
            hasher.update(item.as_canonical_u32().to_le_bytes());
        }
        let result = hasher.finalize();
        BigUint::from_bytes_le(&result).into()
    }

    // Perform EDDSA signature
    fn sign(
        &self,
        message: &[Self::Fb],
        private_key: <Self::P as Params>::Fs,
    ) -> (<Self::P as Params>::Fq, <Self::P as Params>::Fs) {
        let hashed_message = self.hash_message(message);
        let r = self.hash_secret_m(private_key, &hashed_message);

        let point_r: Point<_> = (Self::P::G8 * r).into();
        let point_a: Point<_> = (Self::P::G8 * private_key).into();
        
        let h = self.hash_r_a_m(point_r.x, point_a.x, hashed_message);
        let s = r + h * private_key;
        (point_r.x, s)
    }

    fn verify(
        &self,
        message: &[Self::Fb],
        signature: (<Self::P as Params>::Fq, <Self::P as Params>::Fs),
        public_key: <Self::P as Params>::Fq,
    ) -> bool {
        let _verify = move || {
            let point_r = Point::subgroup_decompress(signature.0)?;
            let point_a = Point::subgroup_decompress(public_key)?;
            let hashed_message = self.hash_message(message);
            let h = self.hash_r_a_m(point_r.x, point_a.x, hashed_message);
            let s_g = Self::P::G8 * signature.1;
            let r_plus_ha = PointProjective::from(point_r) + PointProjective::from(point_a) * h;
            Some(s_g == r_plus_ha)
        };

        _verify().unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::m31::{FqBase, Fs, M31JubJubSigParams};
    use rand::{thread_rng, Rng};

    #[test]
    fn test_eddsa_sign_verify() {
        let sig_params = M31JubJubSigParams::default();
        
        // generate private key
        let private_key: Fs = thread_rng().gen();

        // derive public key
        let public_key = sig_params.public_key(private_key);

        let mut rng = thread_rng();

        // generate random message
        let message: Vec<FqBase> = (0..10).map(|_| rng.gen()).collect();

        // sign the message
        let signature = sig_params.sign(&message, private_key);

        // verify the signature
        let is_valid = sig_params.verify(&message, signature, public_key);

        assert!(is_valid);
    }
}