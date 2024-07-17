include!(concat!(env!("OUT_DIR"), "/methods.rs"));

#[cfg(test)]
mod tests {

    use risc0_zkvm::{default_prover, ExecutorEnv};
    use sha2::{Digest, Sha384};

    use ed25519_dalek::{Signature, Signer, SigningKey};
    use rand::rngs::OsRng;

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

    #[test]
    fn test_verify() -> Result<(), anyhow::Error> {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .with_target(false)
            .init();

        // Precomputed example inputs
        let leaf_data = b"example leaf data";
        let leaf_hash: Vec<u8> = Sha384::digest(leaf_data).to_vec();

        let mut merkle_path: Vec<Vec<u8>> = vec![vec![0; 48]; 32];
        // Fill merkle_path with values from 0 to 31
        for i in 0..32 {
            merkle_path[i][47] = i as u8;
        }

        let computed_root: Vec<u8> = compute_merkle_root(&leaf_hash,  &merkle_path);

        // tracing::info!("computed_root: {:x?}", computed_root);
        // tracing::info!("leaf_hash: {:x?}", leaf_hash);
        // tracing::info!("merkle_path: {:x?}", merkle_path);

        let mut csprng = OsRng {};
        let keypair: SigningKey = SigningKey::generate(&mut csprng);

        let signature: Signature = keypair.sign(&computed_root);

        tracing::info!("env");
        let vk = keypair.verifying_key();
        let signature_input: ([u8; 32], Vec<u8>, Vec<u8>) = (vk.to_bytes(), computed_root.clone(), signature.to_vec());
        println!("{:?}", signature_input);

        let env: ExecutorEnv = ExecutorEnv::builder()
            .write(&signature_input)
            .unwrap()
            .write(&leaf_hash)
            .unwrap()
            .write(&merkle_path)
            .unwrap()
            .build()
            .unwrap();

        let prover = default_prover();
        prover.prove(env, super::MAIN_ELF).unwrap();

        Ok(())

    }
}