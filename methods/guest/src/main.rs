#![no_main]

use sha2::{Sha384, Digest};

use risc0_zkvm::guest::env;

use ed25519_dalek::Verifier;
use ed25519_dalek::{Signature, VerifyingKey};
use core::hint::black_box;

fn compute_merkle_root(leaf: &Vec<u8>, merkle_path: &Vec<Vec<u8>>) -> Vec<u8> {
    let mut current_hash: Vec<u8> = Sha384::digest(leaf).to_vec();

    for sibling in merkle_path {
        let mut hasher = Sha384::new();
        if current_hash < *sibling {
            hasher.update(&current_hash);
            hasher.update(&sibling);
        } else {
            hasher.update(&sibling);
            hasher.update(&current_hash);
        }
        current_hash = hasher.finalize().to_vec();
    }

    current_hash
}

pub fn verify(verifying_key: VerifyingKey, message: &[u8], signature: Signature) {
    // Verify the signature, panicking if verification fails.
    verifying_key
        .verify(&message, &signature)
        .expect("Ed25519 signature verification failed");
}

risc0_zkvm::guest::entry!(main);
fn main() {
    let start = env::cycle_count();

    let (encoded_verifying_key, merkle_root, signature_bytes): ([u8; 32], Vec<u8>, Vec<u8>) = env::read();

    let leaf_hash: Vec<u8> = env::read();
    let merkle_path: Vec<Vec<u8>> = env::read();

    let computed_root = compute_merkle_root(&leaf_hash, &merkle_path);

    assert_eq!(computed_root, merkle_root);

    let diff = env::cycle_count();
    env::log(&format!("cycle count after merkle root: {}", diff - start));


    let verifying_key = VerifyingKey::from_bytes(&encoded_verifying_key).unwrap();
    let signature: Signature = Signature::from_slice(&signature_bytes).unwrap();

    // Verify the signature, panicking if verification fails.
    black_box(verify(
        black_box(verifying_key),
        black_box(&merkle_root),
        black_box(signature),
    ));

    env::commit(&(encoded_verifying_key, merkle_root));

    let diff = env::cycle_count();
    env::log(&format!("total cycle count: {}", diff - start));
}