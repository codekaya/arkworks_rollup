use ark_crypto_primitives::crh::{
    pedersen::{constraints::PedersenCRHGadget, CRH, TwoToOneCRH, Window},
    CRHScheme,
};
use ark_ec::models::twisted_edwards::TEModelParameters;
use ark_ed_on_bls12_381::{EdwardsProjective as JubJub, Fq as Fr, EdwardsParameters};

#[derive(Clone)]
pub struct Window4x256;
impl Window for Window4x256 {
    const WINDOW_SIZE: usize = 4;
    const NUM_WINDOWS: usize = 256;
}

pub type LeafHash = CRH<JubJub, Window4x256>;
pub type LeafHashGadget = PedersenCRHGadget<JubJub, EdwardsParameters, Window4x256>;
pub type TwoToOneHash = TwoToOneCRH<JubJub, Window4x256>;
pub type TwoToOneHashGadget = PedersenCRHGadget<JubJub, EdwardsParameters, Window4x256>;

// Add these type aliases for the Merkle tree configuration
pub type LeafDigest = <LeafHash as CRHScheme>::Output;
pub type InnerDigest = <TwoToOneHash as CRHScheme>::Output;

// Update the config in main.rs to use this hash function
pub type Hash = CRH<JubJub, Window4x256>;
pub type HashGadget = PedersenCRHGadget<JubJub, EdwardsParameters, Window4x256>; 