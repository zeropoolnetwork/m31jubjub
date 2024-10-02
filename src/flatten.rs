use alloc::vec::Vec;


use p3_field::extension::{
    Complex, ComplexExtendable
};
use p3_field::{ExtensionField, Field, PrimeField32, AbstractExtensionField};



pub trait ExtFieldFlattener<From:Sized, To:PrimeField32> : Sized {
    fn flatten_iter(from: &From) -> impl Iterator<Item=&To>;

    fn write_le_bytes_into(from: &From, to: &mut [u8]) {
        let mut i = 0;
        for x in Self::flatten_iter(from) {
            let bytes = x.as_canonical_u32().to_le_bytes();
            i += 4;
            to[i-4..i].copy_from_slice(&bytes);
        }
        assert!(i == to.len());
    }

    fn write_be_bytes_into(from: &From, to: &mut [u8]) {
        let mut i = to.len();
        for x in Self::flatten_iter(from) {
            let bytes = x.as_canonical_u32().to_be_bytes();
            i -= 4;
            to[i..i + 4].copy_from_slice(&bytes);
        }
        assert!(i == 0);
    }
}


pub struct ExtensionFlattener;

impl <From:ExtensionField<To>, To:Field+PrimeField32> ExtFieldFlattener<From, To> for ExtensionFlattener 
{
    fn flatten_iter(from: &From) -> impl Iterator<Item=&To> {
        from.as_base_slice().iter()
    }
}

pub struct ComplexExtensionFlattener;

impl <From:ExtensionField<Complex<To>>, To:ComplexExtendable+PrimeField32> ExtFieldFlattener<From, To> for ComplexExtensionFlattener 
{
    fn flatten_iter(from: &From) -> impl Iterator<Item=&To> {
        from.as_base_slice().iter().flat_map(|x| x.as_base_slice().iter())
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::m31::Fq;
    use rand::{thread_rng, Rng};
    use alloc::vec;

    #[test]
    fn test_write_le_bytes_into() {
        let mut rng = thread_rng();

        let x: Fq = rng.gen();

        let mut x_encoded = vec![0; 32];

        ComplexExtensionFlattener::write_le_bytes_into(&x, &mut x_encoded);

        let expected = bincode::serialize(&x).unwrap();

        assert_eq!(x_encoded, expected);
    }
}