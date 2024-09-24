use alloc::vec::Vec;
use alloc::borrow::{Borrow, ToOwned};

use ark_serialize::CanonicalDeserialize;
use pbkdf2::{/*pbkdf2_hmac,*/ pbkdf2_hmac_array};
use sha2::{Sha256, Sha512, Digest};

use crate::m31::{/*FqBase,*/ Fs/*, M31JubJubSigParams*/};

use crate::bip32;

pub const DICTIONARY: &'static str = include_str!("bip39/english.txt");
pub const PARSED_DICTIONARY: [(usize, usize); 2048] = parse_dict();

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MnemonicError {
    Word(usize),
    Checksum,
    EmptyMnemonic,    
    WrongNumberOfWords,
}

pub fn mnemonic_to_bytes_raw<'a, T, TT>(mnemonic: T) -> Result<Vec<u8>, MnemonicError>
where
    TT: Borrow<str> + 'a,
    T: Borrow<[TT]> + 'a
{
    if mnemonic.borrow().len() == 0 {
        return Err(MnemonicError::EmptyMnemonic);
    }
    let mut res: Vec<u8> = Vec::with_capacity((mnemonic.borrow().len()*11 + 7)/8);
    let mut acc: u128 = 0;
    let mut word_counter = 0;
    let mut power_value = 0;
    for (i, word) in mnemonic.borrow().iter().enumerate() {
        let id = PARSED_DICTIONARY
            .binary_search_by_key(&word.borrow(), |&(begin, end)| &DICTIONARY[begin..end])
            .map_err(|_| MnemonicError::Word(i))?;
//        acc = (acc<<11) + (id as u128);
        acc += (id as u128)<<power_value;
        power_value += 11;
        word_counter += 1;
        if word_counter % 8 == 0 { // lcm(11, 8) = 88;
            res.extend(&u128::to_le_bytes(acc)[..11]);
            acc = 0;
            power_value = 0;
        }
    }
    if word_counter % 8 != 0 {
        res.extend(&u128::to_le_bytes(acc)[..(((word_counter%8)*11 +7) / 8)]);
    }
    Ok(res)
}

pub fn mnemonic_to_bytes_validate<'a, T, TT>(mnemonic: T) -> Result<Vec<u8>, MnemonicError>
where
//    TT: for<'a> Borrow<&'a str> + 'static,
//    T: for<'a> Borrow<&'a [TT]> + 'static
    TT: Borrow<str> + 'a,
    T: Borrow<[TT]> + 'a
{
    if mnemonic.borrow().len() != 12 {
        return Err(MnemonicError::WrongNumberOfWords);
    }
    let bs = mnemonic_to_bytes_raw(mnemonic.borrow())?;
    
    // check mnemonic
    let mut hasher = Sha256::new();
    hasher.update(&bs[..16]);
    let checksum: [u8; 32] = hasher.finalize().into();
    if (checksum[0] & 0x0f) != bs[bs.len()-1] {
//        libc_print::std_name::println!("checksum[0]: {} | bs[bs.len()-1]: {}", checksum[0] & 0x0f, bs[bs.len()-1]);
        return Err(MnemonicError::Checksum);
    }
    Ok(bs)
}

pub fn bytes_to_seed(bs: &[u8], passphrase: &str) -> [u8; 64] {
    const NUMBER_OF_ROUNDS: u32 = 2048;
    let password = bs;
    let salt = "mnemonic".to_owned() + passphrase;
    pbkdf2_hmac_array::<Sha512, 64>(password, salt.as_bytes(), NUMBER_OF_ROUNDS)
}

pub fn seed_to_extended_key(seed: &[u8; 64]) -> Option<bip32::ExtendedKey<Fs>> {
    let key = Fs::deserialize_compressed(&seed[0..31]).ok()?;
    Some(bip32::ExtendedKey {
        is_priv: true,
        network_id: bip32::MAINNET_NETWORK_ID,
        depth: 0,
        fingerprint: bip32::derive_fingerprint(&seed[0..31])?,
        child_num: 0,
        chain_code: {
            let mut tmp = [0u8; 32];
            tmp.copy_from_slice(&seed[32..]);
            tmp
        },
        key,
    })
}

//pub fn mnemonic_add_checksum<'a, T, TT>(mnemonic: T) -> Result<Vec<&'static str>, MnemonicError>
//where
//    TT: Borrow<str> + 'a,
//    T: Borrow<[TT]> + 'a
//{
////    if mnemonic.borrow().len() == 0 || mnemonic.borrow().len() % 8 != 0 {
////        return Err(MnemonicError::WrongNumberOfWords);
////    }
//    let bs = mnemonic_to_bytes_raw(mnemonic.borrow())?;
//    let mut hasher = Sha256::new();
//    hasher.update(&bs[..]);
//    let checksum: [u8; 32] = hasher.finalize().into();
//    let checkbits = mnemonic.borrow().len();
//    let mut checksum_u32: [u8; 4] = [0u8; 4];
//    checksum_u32.copy_from_slice(&checksum[0..4]);
//    let mut acc: u32 = u32::from_le_bytes(checksum_u32);
//    let mut leftbits = checkbits;
//    let mut checkwords = Vec::new();
//    for _ in 0..checkbits {
//        let id = acc & (2048 -1);
//        acc = acc>>11;
//        let (begin, end) = PARSED_DICTIONARY[id as usize];
//        checkwords.push(&DICTIONARY[begin..end]);
//    }
//    Ok(checkwords)
//}

pub fn entropy_to_mnemonic(mut entropy: u128) -> Result<[&'static str; 12], MnemonicError> {
    let entropy_arr = u128::to_le_bytes(entropy);
    let mut hasher = Sha256::new();
    hasher.update(&entropy_arr);
    let hash_arr: [u8; 32] = hasher.finalize().into();
    let checksum = hash_arr[0] & 0x0f;
//    libc_print::std_name::println!("entropy_to_mnemonic: checksum: {}", checksum);
    let mut mnemonic: [&'static str; 12] = [""; 12];
    let mut checksum_is_added = false;
    let mut i = 0;
    while entropy > 0 {
        let id = entropy & (2048-1);
        let (begin, end) = PARSED_DICTIONARY[id as usize];
//        libc_print::std_name::println!("i: {}, entropy: {}", i, entropy);
        mnemonic[i] = &DICTIONARY[begin..end];
        entropy = entropy>>11;
        if !checksum_is_added {
            entropy += (checksum as u128)<<(128 -11);
            checksum_is_added = true;
        }
        i += 1;
    }
    while i < 12 {
        let (begin, end) = PARSED_DICTIONARY[0 as usize];
        mnemonic[i] = &DICTIONARY[begin..end];
        i += 1;
    }
    Ok(mnemonic)
}

pub fn generate_mnemonic() -> ([&'static str; 12], bip32::ExtendedKey<Fs>) {
    use rand::{thread_rng, Rng};

    let mut mnemonic_v;
    let ext;
    loop {
        let entropy: u128 = thread_rng().gen();
        mnemonic_v = entropy_to_mnemonic(entropy).unwrap();
        let bytes = mnemonic_to_bytes_validate(&mnemonic_v[..]).unwrap();
        let seed = bytes_to_seed(&bytes, "");
        match seed_to_extended_key(&seed) {
            Some(ext_) => {
                ext = ext_;
                break;
            },
            None => {
            }
        };
    }
    (mnemonic_v, ext)
}

const fn parse_dict() -> [(usize, usize); 2048] {
    let mut parsed_dict: [(usize, usize); 2048] = [(0, 0); 2048];
    let mut prev = 0;
    let mut i: usize = 0;
    let mut counter = 0;
    while i < DICTIONARY.len() {
        let ch = DICTIONARY.as_bytes()[i];
        if ch < b'a' || ch > b'z' {
            parsed_dict[counter] = (if prev == 0 {prev} else {prev+1}, i);
            prev = i;
            counter += 1;
        }
        i += 1;
    }
    assert!(counter == 2048);
//    parsed_dict[counter] = (if prev == 0 {prev} else {prev+1}, i);
    parsed_dict
}

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn mnemonic_test_001() {
        let (mnemonic_v, ext) = generate_mnemonic();

        libc_print::std_name::println!("{:?}", mnemonic_v);
        libc_print::std_name::println!("{}", ext.encode().unwrap());
    }
}
