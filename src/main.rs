use ark_ff::Field;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_crypto_primitives::merkle_tree::{Config as MerkleConfig, Path};
use ark_crypto_primitives::crh::CRH;
use ark_crypto_primitives::crh::constraints::CRHGadget;
use ark_r1cs_std::prelude::*;
use ark_std::vec::Vec;

struct MyMerkleConfig;
impl MerkleConfig for MyMerkleConfig {
    type LeafHash = SomeHashFunction;
    type TwoToOneHash = SomeHashFunction;
}

pub struct RollupCircuit<F: Field, H: CRH, HG: CRHGadget<H, F>> {
    pub old_root: F,
    pub new_root: F,

    pub merkle_path: Path<MyMerkleConfig>,
    pub old_leaf: F,
    pub new_leaf: F,
    pub transaction_amount: F,
    pub _field_phantom: std::marker::PhantomData<F>,
    pub _hash_phantom: std::marker::PhantomData<(H, HG)>,
}

impl<F: Field, H: CRH, HG: CRHGadget<H, F>> ConstraintSynthesizer<F> for RollupCircuit<F, H, HG> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let old_root_var = FpVar::new_input(cs.clone(), || Ok(self.old_root))?;
        let new_root_var = FpVar::new_input(cs.clone(), || Ok(self.new_root))?;

        let old_leaf_var = FpVar::new_witness(cs.clone(), || Ok(self.old_leaf))?;
        let new_leaf_var = FpVar::new_witness(cs.clone(), || Ok(self.new_leaf))?;
        let tx_amount_var = FpVar::new_witness(cs.clone(), || Ok(self.transaction_amount))?;

        let is_valid_leaf = verify_merkle_path::<
            F, 
            H, 
            HG, 
            MyMerkleConfig
        >(
            cs.clone(),
            &self.merkle_path, 
            &old_root_var, 
            &old_leaf_var
        )?;
        is_valid_leaf.enforce_equal(&Boolean::constant(true))?;

        let computed_new_leaf = old_leaf_var - &tx_amount_var; 
        computed_new_leaf.enforce_equal(&new_leaf_var)?;

        let computed_new_root = update_merkle_root::<F, H, HG, MyMerkleConfig>(
            cs.clone(),
            &self.merkle_path,
            &new_leaf_var
        )?;
        computed_new_root.enforce_equal(&new_root_var)?;

        Ok(())
    }
}
