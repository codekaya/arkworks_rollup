use crate::*;
use ark_bls12_381::Fr;
use ark_ff::UniformRand;
use ark_relations::r1cs::ConstraintSystem;
use ark_crypto_primitives::crh::pedersen::Pedersen;
use ark_std::rand::thread_rng;
use ark_crypto_primitives::crh::CRHScheme;
use ark_crypto_primitives::merkle_tree::MerkleTree;
use crate::state::RollupState;

#[test]
fn test_account_creation() {
    let account = Account {
        balance: Fr::from(1000u32),
        nonce: Fr::from(0u32),
    };
    assert_eq!(account.balance, Fr::from(1000u32));
    assert_eq!(account.nonce, Fr::from(0u32));
}

#[test]
fn test_state_management() {
    let mut state = RollupState::<Fr>::new(32);
    
    // Create and add an account
    let account1 = Account {
        balance: Fr::from(1000u32),
        nonce: Fr::from(0u32),
    };
    
    state.update_account(0, account1.clone());
    
    // Verify account retrieval
    let retrieved_account = state.get_account(0).unwrap();
    assert_eq!(retrieved_account.balance, account1.balance);
    assert_eq!(retrieved_account.nonce, account1.nonce);
}

#[test]
fn test_transaction_processing() {
    let mut rng = thread_rng();
    
    // Initialize state
    let mut state = RollupState::<Fr>::new(32);
    
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
    
    // Create transaction
    let transaction = Transaction {
        from: 0,
        to: 1,
        amount: Fr::from(100u32),
        nonce: Fr::from(0u32),
    };
    
    // Get merkle path and root
    let merkle_path = state.get_merkle_path(transaction.from);
    let old_root = state.get_root();
    
    // Create circuit instance
    let circuit = RollupCircuit::process_transaction(
        account1,
        account2,
        transaction,
        merkle_path,
        old_root,
    ).unwrap();
    
    // Test constraint generation
    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();
    
    // Verify constraints are satisfied
    assert!(cs.is_satisfied().unwrap());
}

#[test]
fn test_invalid_transaction() {
    // Initialize state
    let mut state = RollupState::<Fr>::new(32);
    
    // Create account with insufficient balance
    let account1 = Account {
        balance: Fr::from(50u32),
        nonce: Fr::from(0u32),
    };
    let account2 = Account {
        balance: Fr::from(0u32),
        nonce: Fr::from(0u32),
    };
    
    state.update_account(0, account1.clone());
    state.update_account(1, account2.clone());
    
    // Create transaction with amount greater than balance
    let transaction = Transaction {
        from: 0,
        to: 1,
        amount: Fr::from(100u32),
        nonce: Fr::from(0u32),
    };
    
    let merkle_path = state.get_merkle_path(transaction.from);
    let old_root = state.get_root();
    
    // This should return an error
    let result = RollupCircuit::process_transaction(
        account1,
        account2,
        transaction,
        merkle_path,
        old_root,
    );
    
    assert!(result.is_err());
}

#[test]
fn test_complete_rollup_flow() {
    let mut state = RollupState::<Fr>::new(32);
    
    // Setup initial accounts
    let initial_accounts = vec![
        (0, Account { balance: Fr::from(1000u32), nonce: Fr::from(0u32) }),
        (1, Account { balance: Fr::from(500u32), nonce: Fr::from(0u32) }),
        (2, Account { balance: Fr::from(200u32), nonce: Fr::from(0u32) }),
    ];
    
    // Initialize accounts in state
    for (idx, account) in initial_accounts {
        state.update_account(idx, account);
    }
    
    // Create and process multiple transactions
    let transactions = vec![
        Transaction {
            from: 0,
            to: 1,
            amount: Fr::from(100u32),
            nonce: Fr::from(0u32),
        },
        Transaction {
            from: 1,
            to: 2,
            amount: Fr::from(50u32),
            nonce: Fr::from(0u32),
        },
    ];
    
    // Process each transaction
    for tx in transactions {
        let from_account = state.get_account(tx.from).unwrap().clone();
        let to_account = state.get_account(tx.to).unwrap().clone();
        let merkle_path = state.get_merkle_path(tx.from);
        let old_root = state.get_root();
        
        let circuit = RollupCircuit::process_transaction(
            from_account.clone(),
            to_account.clone(),
            tx.clone(),
            merkle_path,
            old_root,
        ).unwrap();
        
        // Verify constraints
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
        
        // Update state
        state.update_account(tx.from, Account {
            balance: from_account.balance - tx.amount,
            nonce: from_account.nonce + Fr::from(1u32),
        });
        state.update_account(tx.to, Account {
            balance: to_account.balance + tx.amount,
            nonce: to_account.nonce,
        });
    }
    
    // Verify final balances
    let final_account0 = state.get_account(0).unwrap();
    let final_account1 = state.get_account(1).unwrap();
    let final_account2 = state.get_account(2).unwrap();
    
    assert_eq!(final_account0.balance, Fr::from(900u32));  // 1000 - 100
    assert_eq!(final_account1.balance, Fr::from(550u32));  // 500 + 100 - 50
    assert_eq!(final_account2.balance, Fr::from(250u32));  // 200 + 50
} 