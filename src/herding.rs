use crate::md::*;
use std::collections::HashMap;

pub struct DiamondStructure {
    diamond: Vec<HashMap<Vec<u8>, (Vec<u8>, Vec<u8>)>>,
}

impl DiamondStructure {
    pub fn generate(k: u32, hash_size: usize, iv: &[u8]) -> (Self, Vec<u8>) {
        let mut diamond = Vec::<HashMap<Vec<u8>, (Vec<u8>, Vec<u8>)>>::new();

        // Generate 2^k initial messages
        let initial_messages = std::iter::repeat_with(|| {
            std::iter::repeat_with(rand::random::<u8>)
                .take(hash_size)
                .collect::<Vec<u8>>()
        })
        .take(2usize.pow(k))
        .collect::<Vec<Vec<u8>>>();

        // Generate hashes of all those messages
        let mut hashes = initial_messages
            .iter()
            .map(|m| md::<NoPadding>(iv, m))
            .collect::<Vec<Vec<u8>>>();

        // Create our funnel
        while hashes.len() > 1 {
            let mut pairs = HashMap::new();
            let mut next_hashes = Vec::new();

            // Grab hashes two at a time
            for hash_pair in hashes.chunks(2) {
                // Find two messages which hash from this pair of hashes to a common hash value
                let (msg_a, msg_b, common_hash) = find_collision(&hash_pair[0], &hash_pair[1]);

                // Insert a lookup from each hash to the next message and its hash value
                pairs.insert(hash_pair[0].clone(), (msg_a, common_hash.clone()));
                pairs.insert(hash_pair[1].clone(), (msg_b, common_hash.clone()));

                // Keep the hashes for the next iteration
                next_hashes.push(common_hash);
            }
            diamond.push(pairs);
            hashes = next_hashes;
        }

        // 1-block prefix, plus 1-block linking message, plus the diamond blocks
        let length: u128 = (k as u128 + 2) * BLOCKSIZE as u128;
        let length_block = length.to_be_bytes();
        let final_hash = md::<NoPadding>(&hashes[0], &length_block);

        (Self { diamond }, final_hash)
    }

    fn find_linking_message(&self, prefix: &[u8], iv: &[u8]) -> Vec<u8> {
        let iv = md::<NoPadding>(iv, prefix);

        std::iter::repeat_with(|| {
            std::iter::repeat_with(rand::random::<u8>)
                .take(BLOCKSIZE)
                .collect::<Vec<u8>>()
        })
        .find_map(|message| {
            let hash = md_block(&iv, &message);
            if self.diamond[0].contains_key(&hash) {
                Some(message)
            } else {
                None
            }
        })
        .unwrap()
    }

    pub fn create_message(&self, prefix: &[u8], iv: &[u8]) -> Vec<u8> {
        let linking_message = self.find_linking_message(prefix, iv);
        let mut message = prefix.to_vec();
        message.extend(linking_message);
        let mut hash = md::<NoPadding>(iv, &message);
        for index in 0..self.diamond.len() {
            if let Some((block, next_hash)) = self.diamond[index].get(&hash) {
                message.extend(block);
                hash = next_hash.to_vec();
            } else {
                unreachable!()
            }
        }

        message
    }
}

fn find_collision(a: &[u8], b: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut a_hashes = HashMap::<Vec<u8>, Vec<u8>>::new();
    let mut b_hashes = HashMap::<Vec<u8>, Vec<u8>>::new();

    std::iter::repeat_with(|| {
        std::iter::repeat_with(rand::random::<u8>)
            .take(BLOCKSIZE)
            .collect::<Vec<u8>>()
    })
    .find_map(|message| {
        let hash_a = md_block(a, &message);
        if b_hashes.contains_key(&hash_a) {
            Some((message, b_hashes.get(&hash_a).unwrap().clone(), hash_a))
        } else {
            a_hashes.insert(hash_a.clone(), message.clone());
            let hash_b = md_block(b, &message);
            if a_hashes.contains_key(&hash_b) {
                Some((a_hashes.get(&hash_b).unwrap().clone(), message, hash_b))
            } else {
                b_hashes.insert(hash_b, message);
                None
            }
        }
    })
    .unwrap()
}
