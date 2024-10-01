use core::borrow::Borrow;

use super::{PrivateKeyTrait, PublicKeyTrait, To33BytesOblique};
use super::To33Bytes;
use super::{PUB_PRIV_UNION_SIZE, PRIV_SIZE, PUB_SIZE};

use ark_serialize::{CanonicalSerialize, CanonicalDeserialize, Compress, Validate};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum KeyTypes<Priv, Pub>
where
    Priv: PrivateKeyTrait,
    Pub: PublicKeyTrait,
{
    Private(Priv),
    Public(Pub),
}

//impl<Priv, Pub> From<Priv> for KeyTypes<Priv, Pub>
//where
//    Priv: PrivateKeyTrait,
//    Pub: PublicKeyTrait,
//{
//    fn from(p: Priv) -> Self {
//        Self::Private(p)
//    }
//}
//
//impl<Priv, Pub> From<Pub> for KeyTypes<Priv, Pub>
//where
//    Priv: PrivateKeyTrait,
//    Pub: PublicKeyTrait,
//{
//    fn from(p: Pub) -> Self {
//        Self::Public(p)
//    }
//}


impl<Priv, Pub> KeyTypes<Priv, Pub>
where
    Priv: PrivateKeyTrait,
    Pub: PublicKeyTrait,
{

    pub fn is_priv(&self) -> bool {
        match self {
            Self::Private(_) => true,
            _ => false,
        }
    }

    pub fn private(&self) -> Option<&Priv> {
        match self {
            Self::Private(k) => Some(k),
            _ => None
        }
    }
    pub fn public(&self) -> Option<&Pub> {
        match self {
            Self::Public(k) => Some(k),
            _ => None
        }
    }

    pub fn from_priv(p: Priv) -> Self {
        Self::Private(p)
    }
    pub fn from_pub(p: Pub) -> Self {
        Self::Public(p)
    }
}

impl<Priv, Pub> KeyTypes<Priv, Pub>
where
    Priv: PrivateKeyTrait + CanonicalDeserialize,
    Pub: PublicKeyTrait
{
    pub fn from_bytes_priv<T>(t: T) -> Option<Self>
    where
        T: Borrow<[u8]>
    {
        let bs = t.borrow();
        Some(Self::from_priv(Priv::deserialize_compressed(bs).ok()?))
    }
}

impl<Priv, Pub> KeyTypes<Priv, Pub>
where
    Priv: PrivateKeyTrait,
    Pub: PublicKeyTrait + for<'a> serde::Deserialize<'a>,
{
    pub fn from_bytes_pub<T>(t: T) -> Option<Self>
    where
        T: Borrow<[u8]>
    {
        let bs = t.borrow();
        Some(Self::from_pub(bincode::deserialize(bs).ok()?))
    }
}

impl<Priv, Pub> To33BytesOblique for KeyTypes<Priv, Pub>
where
    Priv: PrivateKeyTrait,
    Pub: PublicKeyTrait,
{
    fn to_33_bytes(&self, target: &mut [u8]) -> Option<()> {
        if target.len() != PUB_PRIV_UNION_SIZE {
            return None;
        }
        if self.is_priv() {
            self.private().and_then(|p| p.to_33_bytes(target))
        } else {
            self.public().and_then(|p| p.to_33_bytes(target))
        }
    }

    fn padding(&self) -> usize {
        if self.is_priv() {
            Priv::PADDING_LEN
        } else {
            Pub::PADDING_LEN
        }
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
