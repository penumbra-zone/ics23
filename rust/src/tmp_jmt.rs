use alloc::vec::Vec;
use jmt::{mock::MockTreeStore, JellyfishMerkleTree, KeyHash, RootHash, ValueHash};

/// The length of the hash in bytes.
pub const LENGTH: usize = 32;
/// The length of the hash in bits.
pub const LENGTH_IN_BITS: usize = LENGTH * 8;
use ripemd160::Digest;
use sha2::Sha256;

fn hash_leaf_node(key_hash: &KeyHash, value_hash: &ValueHash) -> [u8; 32] {
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"JMT::LeafNode");
    hasher.update(key_hash.0);
    hasher.update(value_hash.0);
    *hasher.finalize().as_ref()
}

fn hash_internal_node(left_child: &[u8; 32], right_child: &[u8; 32]) -> [u8; 32] {
    let mut hasher = sha2::Sha256::new();
    // chop a vowel to fit in 16 bytes
    hasher.update(b"JMT::IntrnalNode");
    hasher.update(&left_child);
    hasher.update(&right_child);
    *hasher.finalize().as_ref()
}

pub struct TestExistenceProof {
    pub key_hash: KeyHash,
    pub value_hash: ValueHash,
    pub siblings: Vec<[u8; 32]>,
}

impl TestExistenceProof {
    pub fn verify(
        &self,
        expected_root_hash: RootHash,
        element_key: KeyHash,
        element_hash: ValueHash,
    ) -> Result<(), &'static str> {
        if element_key != self.key_hash {
            return Err("Element key does not match proof key.");
        }

        if element_hash != self.value_hash {
            return Err("Element value hash does not match proof value hash.");
        }

        let mut current_hash = hash_leaf_node(&self.key_hash, &self.value_hash);

        let mut skip = 256 - self.siblings.len();
        let mut sibling_idx = 0;
        for byte_idx in (0..32).rev() {
            // The JMT proofs iterate over the bits in MSB order
            for bit_idx in 0..8 {
                if skip > 0 {
                    skip -= 1;
                    continue;
                } else {
                    let bit = (self.key_hash.0[byte_idx] >> bit_idx) & 0x1;
                    current_hash = if bit == 1 {
                        hash_internal_node(&self.siblings[sibling_idx], &current_hash)
                    } else {
                        hash_internal_node(&current_hash, &self.siblings[sibling_idx])
                    };
                    sibling_idx += 1;
                }
            }
        }

        let actual_root_hash = current_hash;

        if actual_root_hash == expected_root_hash.0 {
            Ok(())
        } else {
            Err("Root hashes do not match.")
        }
    }
}

#[test]
fn test_ics23() {
    let db = MockTreeStore::default();
    let tree = JellyfishMerkleTree::new(&db);

    // Tree is initially empty. Root is a null node. We'll insert a key-value pair which creates a
    // leaf node.
    let key1 = KeyHash::from([1; 32]);
    let key2 = KeyHash::from({
        let mut bytes = [2; 32];
        bytes[0] = 1;
        bytes
    });

    let value = vec![1u8, 2u8, 3u8, 4u8];

    // batch version
    let (new_root_hash, batch) = tree
        .batch_put_value_sets(
            vec![vec![(key1, value.clone()), (key2, value)]],
            None,
            0, /* version */
        )
        .unwrap();

    assert!(batch.stale_node_index_batch.is_empty());

    db.write_tree_update_batch(batch).unwrap();

    let (value, proof) = tree.get_with_proof(key1, 0).unwrap();

    // Convert the JMT SparseMerkleProof into ICS23 tmp proof?

    let ics23_proof = TestExistenceProof {
        key_hash: proof.leaf().unwrap().key_hash(),
        value_hash: ValueHash::from(&value.as_ref().unwrap()),
        siblings: proof.siblings().to_vec(),
    };

    println!("testing jmt verify");
    proof
        .verify(new_root_hash[0], key1, Some(&value.as_ref().unwrap()))
        .unwrap();

    println!("testing ics23 verify");
    ics23_proof
        .verify(new_root_hash[0], key1, ValueHash::from(&value.unwrap()))
        .unwrap();

    panic!();
}
