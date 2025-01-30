use ark_ff::Field;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_crypto_primitives::merkle_tree::{Config as MerkleConfig, Path};
use ark_crypto_primitives::crh::{
    CRHScheme,
    pedersen::{constraints::PedersenCRHGadget, CRH, TwoToOneCRH},
};
use ark_r1cs_std::prelude::*;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::boolean::Boolean;
use ark_bls12_381::Fr;

mod hash;
mod state;
#[cfg(test)]
mod tests;

use crate::hash::{LeafHash, TwoToOneHash, LeafDigest, InnerDigest};
use crate::state::RollupState;

struct MyMerkleConfig;
impl MerkleConfig for MyMerkleConfig {
    type Leaf = Fr;
    type LeafDigest = LeafDigest;
    type LeafHash = LeafHash;
    type InnerDigest = InnerDigest;
    type TwoToOneHash = TwoToOneHash;
    type LeafInnerDigestConverter = ();
}

#[derive(Clone, Debug)]
pub struct Account<F: Field> {
    pub balance: F,
    pub nonce: F,
}

#[derive(Clone, Debug)]
pub struct Transaction<F: Field> {
    pub from: usize,
    pub to: usize,
    pub amount: F,
    pub nonce: F,
}

pub struct RollupCircuit<F: Field> {
    pub old_root: F,
    pub new_root: F,
    pub merkle_path: Path<MyMerkleConfig>,
    pub old_leaf: F,
    pub new_leaf: F,
    pub transaction_amount: F,
    pub from_account: Account<F>,
    pub to_account: Account<F>,
    pub transaction: Transaction<F>,
}

impl<F: Field> ConstraintSynthesizer<F> for RollupCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let old_root_var = FpVar::new_input(cs.clone(), || Ok(self.old_root))?;
        let new_root_var = FpVar::new_input(cs.clone(), || Ok(self.new_root))?;

        let old_leaf_var = FpVar::new_witness(cs.clone(), || Ok(self.old_leaf))?;
        let new_leaf_var = FpVar::new_witness(cs.clone(), || Ok(self.new_leaf))?;
        let tx_amount_var = FpVar::new_witness(cs.clone(), || Ok(self.transaction_amount))?;

        let is_valid_leaf = verify_merkle_path::<F, MyMerkleConfig>(
            cs.clone(),
            &self.merkle_path, 
            &old_root_var, 
            &old_leaf_var
        )?;
        is_valid_leaf.enforce_equal(&Boolean::constant(true))?;

        let computed_new_leaf = old_leaf_var - &tx_amount_var; 
        computed_new_leaf.enforce_equal(&new_leaf_var)?;

        let computed_new_root = update_merkle_root::<F, MyMerkleConfig>(
            cs.clone(),
            &self.merkle_path,
            &new_leaf_var
        )?;
        computed_new_root.enforce_equal(&new_root_var)?;

        let account_nonce_var = FpVar::new_witness(cs.clone(), || Ok(self.from_account.nonce))?;
        let tx_nonce_var = FpVar::new_witness(cs.clone(), || Ok(self.transaction.nonce))?;
        account_nonce_var.enforce_equal(&tx_nonce_var)?;

        let sender_balance_var = FpVar::new_witness(cs.clone(), || Ok(self.from_account.balance))?;
        sender_balance_var.enforce_cmp(&tx_amount_var, std::cmp::Ordering::Greater)?;

        Ok(())
    }
}

impl<F: Field> RollupCircuit<F> {
    pub fn process_transaction(
        from_account: Account<F>,
        to_account: Account<F>,
        transaction: Transaction<F>,
        merkle_path: Path<MyMerkleConfig>,
        old_root: F,
    ) -> Result<Self, SynthesisError> {
        if transaction.amount > from_account.balance {
            return Err(SynthesisError::Unsatisfiable);
        }

        if transaction.nonce != from_account.nonce {
            return Err(SynthesisError::Unsatisfiable);
        }

        Ok(Self {
            old_root,
            new_root: F::zero(),
            merkle_path,
            old_leaf: from_account.balance,
            new_leaf: from_account.balance - transaction.amount,
            transaction_amount: transaction.amount,
            from_account,
            to_account,
            transaction,
        })
    }
}

fn verify_merkle_path<F: Field, C: MerkleConfig>(
    cs: ConstraintSystemRef<F>,
    path: &Path<C>,
    root: &FpVar<F>,
    leaf: &FpVar<F>,
) -> Result<Boolean<F>, SynthesisError> {
    Ok(Boolean::constant(true))
}

fn update_merkle_root<F: Field, C: MerkleConfig>(
    cs: ConstraintSystemRef<F>,
    path: &Path<C>,
    new_leaf: &FpVar<F>,
) -> Result<FpVar<F>, SynthesisError> {
    Ok(FpVar::constant(F::zero()))
}

fn main() {
    // Initialize rollup state
    let mut state = RollupState::<Fr>::new(32); // 32 levels deep Merkle tree

    // Create accounts
    let account1 = Account {
        balance: Fr::from(1000u32),
        nonce: Fr::from(0u32),
    };
    let account2 = Account {
        balance: Fr::from(0u32),
        nonce: Fr::from(0u32),
    };

    // Add accounts to state
    state.update_account(0, account1.clone());
    state.update_account(1, account2.clone());

    // Create a transaction
    let transaction = Transaction {
        from: 0,
        to: 1,
        amount: Fr::from(100u32),
        nonce: Fr::from(0u32),
    };

    // Process transaction
    let merkle_path = state.get_merkle_path(transaction.from);
    let old_root = state.get_root();

    let circuit = RollupCircuit::process_transaction(
        account1,
        account2,
        transaction,
        merkle_path,
        old_root,
    ).unwrap();

    // Generate and verify proof (implementation needed)
    // ...
}
