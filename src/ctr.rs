use crate::ecb::ecb_encrypt_without_padding;
use std::collections::VecDeque;

// Iterator to generate a key stream
pub struct KeyStreamIterator {
    counter: u64,
    key: Vec<u8>,
    nonce: u64,
    blocksize: usize,
    key_block: VecDeque<u8>,
}

impl KeyStreamIterator {
    // Generate a keystream from the given key, and nonce
    pub fn new(key: &[u8], nonce: u64, blocksize: usize) -> Self {
        Self {
            counter: 0,
            key: key.to_vec(),
            nonce,
            blocksize,
            key_block: VecDeque::new(),
        }
    }

    pub fn next_block(&mut self) {
        // Nonce || a counter
        let mut nonce_and_counter = self.nonce.to_le_bytes().to_vec();
        nonce_and_counter.extend(self.counter.to_le_bytes().to_vec());
        self.counter += 1;

        // Generate the key block by encrypting the nonce-and-counter with the key
        self.key_block = VecDeque::from(ecb_encrypt_without_padding(
            &self.key,
            &nonce_and_counter,
            self.blocksize,
        ));
    }
}

impl Iterator for KeyStreamIterator {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        if self.key_block.is_empty() {
            self.next_block();
        }
        self.key_block.pop_front()
    }
}

// Once we have the keystream set up, this part is easy-peazy
// Zip the keystream with the input, xor them, and Bob's your uncle
pub fn ctr(key: &[u8], nonce: u64, input: &[u8], blocksize: usize) -> Vec<u8> {
    KeyStreamIterator::new(key, nonce, blocksize)
        .zip(input.iter())
        .map(|(k, p)| k ^ *p)
        .collect()
}
