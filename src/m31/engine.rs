


use p3_poseidon2::{Poseidon2, Poseidon2ExternalMatrixGeneral};
use p3_mersenne_31::DiffusionMatrixMersenne31;
use p3_symmetric::PaddingFreeSponge;

use crate::eddsa::SigParams;
use crate::curve::{Params, PointProjective};
use crate::m31::{Fq, FqBase, Fs, fq_new_from_raw};
use crate::flatten::ComplexExtensionFlattener;

use primitives::poseidon2_m31_hash;

type Perm = Poseidon2<FqBase, Poseidon2ExternalMatrixGeneral, DiffusionMatrixMersenne31, 16, 5>;
type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;

#[derive(Clone, Copy, Debug)]
pub struct M31JubJubParams;

impl Params for M31JubJubParams {
    type Fq = Fq;
    type Fs = Fs;
    const D: Self::Fq = fq_new_from_raw([1530180101, 1286903024, 823193794, 1929909262, 1865204271, 2066283225, 1349906444, 1236191318]);
    const G: PointProjective<Self> = PointProjective::new(
        fq_new_from_raw([1877637187, 625092471, 853537684, 1907750992, 1052633189, 1084608143, 945110118, 455926870]),
        fq_new_from_raw([1167994, 892421824, 143521621, 1692807047, 160338294, 1935691581, 1461160856, 412915271]),
        fq_new_from_raw([1, 0, 0, 0, 0, 0, 0, 0])
    );
    const G8: PointProjective<Self> = PointProjective::new(
        fq_new_from_raw([1279048008, 1484784720, 586032070, 1548213212, 2250614, 1782435982, 1582651553, 1683330946]),
        fq_new_from_raw([1501552815, 1089547304, 1572871942, 1429284693, 1149181451, 1293690843, 2134715099, 1973006813]),
        fq_new_from_raw([1, 0, 0, 0, 0, 0, 0, 0])
    );
}


#[derive(Clone)]
pub struct M31JubJubSigParams {
    hasher: MyHash 
}

impl M31JubJubSigParams {
    pub fn new(hasher: MyHash) -> Self {
        Self { hasher }
    }
}

impl Default for M31JubJubSigParams {
    fn default() -> Self {    
        M31JubJubSigParams::new(poseidon2_m31_hash())
    }
}

impl SigParams<8> for M31JubJubSigParams
{
    type P = M31JubJubParams;
    type HasherOut = [Fq; 8];
    type Fb = FqBase;
    type Flattener = ComplexExtensionFlattener;
    type Hasher = MyHash;

    fn get_hasher(&self) -> &Self::Hasher {
        &self.hasher
    }
}

