use crate::pkcs7::Serialize;
use crate::util::{generate_random_bytes, get_padding_size, xor};
use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;
use rand::{self, Rng};
use std::collections::VecDeque;

pub fn generate_key(blocksize: usize) -> Vec<u8> {
    generate_random_bytes(blocksize)
}

pub fn generate_iv(blocksize: usize) -> Vec<u8> {
    generate_random_bytes(blocksize)
}

pub fn encryption_oracle(key: &[u8], plaintext: &[u8], blocksize: usize) -> (Vec<u8>, bool) {
    let prefix_size = rand::thread_rng().gen_range(5..10);
    let suffix_size = rand::thread_rng().gen_range(5..10);

    let mut to_encrypt: Vec<u8> = Vec::new();
    (0..prefix_size).for_each(|_| to_encrypt.push(rand::random()));
    to_encrypt.extend_from_slice(plaintext);
    (0..suffix_size).for_each(|_| to_encrypt.push(rand::random()));

    if rand::random() {
        (ecb_encrypt(key, &to_encrypt, blocksize), true)
    } else {
        (
            cbc_encrypt(key, &generate_iv(blocksize), &to_encrypt, blocksize),
            false,
        )
    }
}

pub fn ecb_encrypt_with_prefix_and_suffix(
    key: &[u8],
    plaintext: &[u8],
    prefix: &[u8],
    suffix: &[u8],
    blocksize: usize,
) -> Vec<u8> {
    let mut payload = vec![];
    payload.extend(prefix);
    payload.extend(plaintext);
    payload.extend(suffix);

    ecb_encrypt(key, &payload, blocksize)
}

pub fn ecb_decrypt(key: &[u8], ciphertext: &[u8], blocksize: usize) -> Vec<u8> {
    let cipher = Aes128::new(GenericArray::from_slice(key));
    ciphertext
        .chunks(blocksize)
        .flat_map(|chunk| {
            let mut block = *GenericArray::from_slice(chunk);
            cipher.decrypt_block(&mut block);
            block.to_vec()
        })
        .collect::<Vec<u8>>()
}

fn ecb_encrypt_without_padding(key: &[u8], plaintext: &[u8], blocksize: usize) -> Vec<u8> {
    let cipher = Aes128::new(GenericArray::from_slice(key));
    plaintext
        .chunks(blocksize)
        .flat_map(|chunk| {
            let mut block = *GenericArray::from_slice(chunk);
            cipher.encrypt_block(&mut block);
            block.to_vec()
        })
        .collect()
}

pub fn ecb_encrypt(key: &[u8], plaintext: &[u8], blocksize: usize) -> Vec<u8> {
    ecb_encrypt_without_padding(key, &plaintext.pkcs7_serialize(blocksize), blocksize)
}

// CBC mode using ECB
// c = e(cp ^ p)
// where c is the ciphertext, cp is the previous ciphertext (or iv), p is the plaintext and e is
// the encryption function
pub fn cbc_encrypt(key: &[u8], iv: &[u8], plaintext: &[u8], blocksize: usize) -> Vec<u8> {
    let (_, output) = plaintext.pkcs7_serialize(blocksize).chunks(blocksize).fold(
        (iv.to_vec(), Vec::new()),
        |(prev_ciphertext, mut output), chunk| {
            // Xor with previous ciphertext, then encrypt
            let encrypted =
                ecb_encrypt_without_padding(key, &xor(&prev_ciphertext, chunk).unwrap(), blocksize);
            output.extend(encrypted.clone());
            (encrypted, output)
        },
    );

    output
}

// CBC mode using ECB
// p = cp ^ d(c)
// where c is the ciphertext, cp is the previous ciphertext (or iv), p is the plaintext and d is
// the decryption function
pub fn cbc_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8], blocksize: usize) -> Vec<u8> {
    let (_, output) = ciphertext.chunks(blocksize).fold(
        (iv.to_vec(), Vec::new()),
        |(prev_ciphertext, mut output), chunk| {
            // Decrypt, then xor with previous ciphertext
            output.extend(&xor(&prev_ciphertext, &ecb_decrypt(key, chunk, blocksize)).unwrap());
            (chunk.to_vec(), output)
        },
    );

    output
}

// Detect AES in ECB mode by encrypting a long string and looking for identical blocks of
// ciphertext
pub fn detect_ecb(ciphertext: &[u8], blocksize: usize) -> bool {
    let mut chunks = ciphertext.chunks(blocksize).collect::<Vec<&[u8]>>();
    while let Some(chunk) = chunks.pop() {
        if chunks.iter().any(|other| *other == chunk) {
            return true;
        }
    }

    false
}

// Find the blocksize by encrypting longer strings until the ciphertext length changes.
// The blocksize will be the difference in lengths
pub fn find_blocksize<F: Fn(&[u8]) -> Vec<u8>>(encrypt_fn: &F) -> Option<usize> {
    let mut plaintext = vec![];
    let initial = encrypt_fn(&plaintext).len();
    for size in 0..2048 {
        plaintext = vec![b'A'; size];
        let ciphertext = encrypt_fn(&plaintext);
        if ciphertext.len() != initial {
            return Some(ciphertext.len() - initial);
        }
    }

    None
}

// Here we get the prefix size of an encryption function by starting with two blocks of plaintext
// filled with the same character, and then add chars until we get two ciphertext blocks that are
// identical - this means that the prefix is the number of blocks before the identical ciphertext
// blocks, minus the added characters
pub fn get_prefix_size<F: Fn(&[u8]) -> Vec<u8>>(encrypt_fn: &F, blocksize: usize) -> Option<usize> {
    let mut plaintext = std::iter::repeat(b'A')
        .take(blocksize * 2)
        .collect::<Vec<u8>>();
    for padding in 0usize..(100 * blocksize) {
        let ciphertext = encrypt_fn(&plaintext);
        let blocks = ciphertext.chunks(blocksize).collect::<Vec<&[u8]>>();
        for i in 0..blocks.len() - 1 {
            if blocks[i] == blocks[i + 1] {
                return Some(blocksize * i - padding);
            }
        }
        plaintext.push(b'A');
    }

    None
}

// Pad out the prefix to a full block, then add chars to the plaintext until we go over a block
// boundary, and count from there
pub fn get_suffix_size<F: Fn(&[u8]) -> Vec<u8>>(
    encrypt_fn: &F,
    prefix_size: usize,
    blocksize: usize,
) -> Option<usize> {
    let mut plaintext = vec![];
    let prefix_padding = get_padding_size(prefix_size, blocksize);
    plaintext.extend(
        std::iter::repeat(b'A')
            .take(prefix_padding)
            .collect::<Vec<u8>>(),
    );
    let ciphertext = encrypt_fn(&plaintext);
    let initial_size = ciphertext.len();
    for padding in 1usize..(blocksize - 1) {
        plaintext.push(b'A');
        let ciphertext = encrypt_fn(&plaintext);
        if ciphertext.len() != initial_size {
            // Initial size is the suffix + prefix pushed to block boundary
            // so take initial size, subtract the prefix stuff, and subtract our padding
            // (since it'll jump up once we hit a block boundary)
            return Some(initial_size - (prefix_size + prefix_padding) - padding);
        }
    }

    None
}

pub fn byte_by_byte_ecb_decrypt<F: Fn(&[u8]) -> Vec<u8>>(
    encrypt_fn: &F,
    prefix_size: usize,
    suffix_size: usize,
    blocksize: usize,
) -> Option<Vec<u8>> {
    // Figure out how much to pad to get the suffix on a block boundary,
    let padding = get_padding_size(prefix_size + suffix_size, blocksize);

    // Make our test string big enough to contain the suffix, and also move the suffix to a block
    // boundary
    let test_string_size = suffix_size + padding;

    // Empty solution vector
    let mut solution = vec![];

    for pos in 1..test_string_size + 1 {
        // Create our test string
        let mut test_string = std::iter::repeat(b'A')
            .take(test_string_size - pos)
            .collect::<Vec<u8>>();

        // Encrypt
        let ciphertext = encrypt_fn(&test_string);

        // Add our partial solution
        test_string.extend(&solution);
        test_string.push(0u8);

        // Find the character
        match (0u8..b'~').find(|ch| {
            test_string[test_string_size - 1] = *ch;
            let test = encrypt_fn(&test_string);
            ciphertext[..prefix_size + test_string_size] == test[..prefix_size + test_string_size]
        }) {
            Some(ch) => {
                // If we hit 0x1, that means we've finished, because we've hit the padding
                if ch == 0x1 {
                    return Some(solution);
                };
                solution.push(ch)
            }
            None => return None,
        }
    }

    Some(solution)
}

fn decrypt_block_byte_at_a_time<F: Fn(&[u8], &[u8]) -> bool>(
    block_num: usize,
    iv: &[u8],
    ciphertext: &[u8],
    blocksize: usize,
    validation_fn: &F,
) -> Vec<u8> {
    let mut solution = vec![];

    // If we're at the first block, we modify the IV, otherwise, the actual ciphertext
    // blocks
    let mut block = match block_num {
        0 => iv.to_vec(),
        _ => ciphertext.to_vec(),
    };

    // Iterate backwards through the bytes in the block
    for byte_index in (0usize..blocksize).rev() {
        // Since we might be in the IV or the ciphertext, have to index them differently
        let index = match block_num {
            0 => byte_index,
            _ => (block_num - 1) * blocksize + byte_index,
        };

        // Hold onto the original value
        let original_value = block[index];

        // Figure out the proper padding value
        let padding_value: u8 = (blocksize - byte_index) as u8;

        // Find the changed byte value that passes the padding validation
        match (0u8..=255).find(|byte_value| {
            block[index] = *byte_value;
            *byte_value != original_value
                && match block_num {
                    0 => validation_fn(&block, ciphertext),
                    _ => validation_fn(iv, &block),
                }
        }) {
            // Found a value that works
            Some(value) => {
                // We know that:
                //   plaintext = decrypt(ciphertext) ^ original_value
                // Also:
                //   padding_value = decrypt(ciphertext) ^ value
                // So:
                //   plaintext ^ padding_value = decrypt(ciphertext) ^ decrypt(ciphertext) ^ value ^ original_value
                //                             = value ^ original_value
                // therefore
                //   plaintext = value ^ padding_value ^ original_value
                solution.push(value ^ padding_value ^ original_value);
            }

            // We didn't find it, chances are, because it's the first byte of
            // padding. We push the padding value as our solution, and return the original value
            None => {
                solution.push(padding_value);
                block[index] = original_value;
            }
        };

        // Reset the already-done bytes for the next padding value
        let end = match block_num {
            0 => blocksize,
            _ => block_num * blocksize,
        };
        for byte in block.iter_mut().take(end).skip(index) {
            *byte ^= padding_value ^ (padding_value + 1);
        }
    }

    solution
}

pub fn decrypt_byte_at_a_time<F: Fn(&[u8], &[u8]) -> bool>(
    iv: &[u8],
    ciphertext: &[u8],
    blocksize: usize,
    validation_fn: &F,
) -> Vec<u8> {
    let mut solution = vec![];
    for block_num in (0..ciphertext.len() / blocksize).rev() {
        solution.extend(decrypt_block_byte_at_a_time(
            block_num,
            iv,
            &ciphertext.clone()[..(block_num + 1) * blocksize],
            blocksize,
            validation_fn,
        ));
    }

    solution.reverse();
    solution
}

struct KeyStreamIterator {
    counter: u64,
    key: Vec<u8>,
    nonce: u64,
    blocksize: usize,
    key_block: VecDeque<u8>,
}

impl KeyStreamIterator {
    fn new(key: &[u8], nonce: u64, blocksize: usize) -> Self {
        Self {
            counter: 0,
            key: key.to_vec(),
            nonce,
            blocksize,
            key_block: VecDeque::new(),
        }
    }

    fn next_block(&mut self) {
        let mut nonce_and_counter = self.nonce.to_le_bytes().to_vec();
        nonce_and_counter.extend(self.counter.to_le_bytes().to_vec());
        self.counter += 1;
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

pub fn ctr(key: &[u8], nonce: u64, input: &[u8], blocksize: usize) -> Vec<u8> {
    KeyStreamIterator::new(key, nonce, blocksize)
        .zip(input.iter())
        .map(|(k, p)| k ^ *p)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pkcs7::*;

    #[test]
    fn test_aes_ecb() {
        let plaintext = "THIS IS MY PLAINTEXT";
        let key = "YELLOW SUBMARINE";
        let ciphertext = ecb_encrypt(key.as_bytes(), plaintext.as_bytes(), 16);
        assert_eq!(
            plaintext.as_bytes(),
            &ecb_decrypt(key.as_bytes(), &ciphertext, 16)
                .pkcs7_deserialize(16)
                .unwrap(),
        );
    }

    #[test]
    fn test_aes_cbc() {
        let plaintext = "THIS IS MY PLAINTEXT";
        let key = "YELLOW SUBMARINE";
        let iv = generate_iv(16);
        let ciphertext = cbc_encrypt(key.as_bytes(), &iv, plaintext.as_bytes(), 16);
        assert_eq!(
            plaintext.as_bytes(),
            &cbc_decrypt(key.as_bytes(), &iv, &ciphertext, 16)
                .pkcs7_deserialize(16)
                .unwrap(),
        );
    }

    #[test]
    fn test_get_prefix_size() {
        let prefix = "YELLOW SUBMARINE PREFIX".as_bytes();
        let key = "YELLOW SUBMARINE".as_bytes();
        let encryption_fn = |plaintext: &[u8]| {
            let mut to_be_encrypted = vec![];
            to_be_encrypted.extend(prefix);
            to_be_encrypted.extend(plaintext);
            ecb_encrypt(key, &to_be_encrypted, 16)
        };
        let prefix_size = get_prefix_size(&encryption_fn, 16).unwrap();
        assert_eq!(prefix.len(), prefix_size);
    }

    #[test]
    fn test_get_suffix_size() {
        let prefix = "YELLOW SUBMARINE PREFIX".as_bytes();
        let suffix = "YELLOW SUBMARINE SUFFIX".as_bytes();
        let key = "YELLOW SUBMARINE".as_bytes();
        let encryption_fn = |plaintext: &[u8]| {
            let mut to_be_encrypted = vec![];
            to_be_encrypted.extend(prefix);
            to_be_encrypted.extend(plaintext);
            to_be_encrypted.extend(suffix);
            ecb_encrypt(key, &to_be_encrypted, 16)
        };
        let suffix_size = get_suffix_size(&encryption_fn, prefix.len(), 16).unwrap();
        assert_eq!(suffix.len(), suffix_size);
    }
}
