use ark_ff::Field;
use ark_crypto_primitives::merkle_tree::{MerkleTree, Path};
use std::collections::HashMap;
use crate::{Account, MyMerkleConfig};

#[derive(Clone)]
pub struct RollupState<F: Field> {
    pub merkle_tree: MerkleTree<MyMerkleConfig>,
    pub accounts: HashMap<usize, Account<F>>,
}

impl<F: Field> RollupState<F> {
    pub fn new(height: usize) -> Self {
        Self {
            merkle_tree: MerkleTree::new(height, &Vec::new()).unwrap(),
            accounts: HashMap::new(),
        }
    }

    pub fn get_account(&self, index: usize) -> Option<&Account<F>> {
        self.accounts.get(&index)
    }

    pub fn update_account(&mut self, index: usize, account: Account<F>) {
        self.accounts.insert(index, account);
        // Update Merkle tree
        self.merkle_tree.update(index, &account.balance).unwrap();
    }

    pub fn get_merkle_path(&self, index: usize) -> Path<MyMerkleConfig> {
        self.merkle_tree.generate_proof(index).unwrap()
    }

    pub fn get_root(&self) -> F {
        self.merkle_tree.root()
    }
} 