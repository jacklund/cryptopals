use crate::ecb::ecb_encrypt_without_padding;
use crate::mt19937::{B, C, L, S, T, U};
use crate::util::{
    create_histogram, get_padding_size, hamming_distance, keystream_from_byte, try_xor_key,
};
use lazy_static::lazy_static;
use std::collections::VecDeque;

pub const ETAOIN: &str =
    " \neEtTaAoOiInNsShHrRlLdDuUcCmMwWyYfFgGpPbBvVkKjJxXqQzZ0123456789.,!?'\":;-";

lazy_static! {
    pub static ref CHAR_LIST_BY_FREQUENCY: Vec<u8> = {
        ETAOIN
            .bytes()
            .flat_map(|b| {
                if b as char == ' ' {
                    vec![b]
                } else {
                    vec![
                        b,
                        (b as char).to_uppercase().collect::<Vec<char>>()[0] as u8,
                    ]
                }
            })
            .collect()
    };
}

/// Repeat the key string until it's the same length as the plaintext, and then xor it with the
/// plaintext
pub fn repeating_key_xor(key: &[u8], plaintext: &[u8]) -> Vec<u8> {
    key.iter()
        .cycle()
        .take(plaintext.len())
        .zip(plaintext)
        .map(|(k, p)| k ^ p)
        .collect()
}

/// Since `p ^ k = c`, where `p` is the plaintext char, `k` is the key char, and `c` is the
/// ciphertext char, we can use `k = c ^ p`. Here, we take the most frequent char in the
/// ciphertext, and xor it with each of the most frequent chars in the English language,
/// and try that as a key. The key that gives us the highest score wins.
pub fn find_single_byte_key(ciphertext: &[u8]) -> (u8, usize, String) {
    let histogram = create_histogram(ciphertext);
    let ciphertext_val = histogram[0].0;

    CHAR_LIST_BY_FREQUENCY.iter().fold(
        (0u8, 0usize, String::new()),
        |(last_key, last_score, last_plaintext), b| {
            let key = *b ^ ciphertext_val;
            let (score, plaintext) = try_xor_key(
                &keystream_from_byte(*b ^ ciphertext_val, ciphertext.len()),
                ciphertext,
            );
            if score > last_score {
                (key, score, plaintext)
            } else {
                (last_key, last_score, last_plaintext)
            }
        },
    )
}

/// Three steps:
/// - Try different keysizes, chunk the ciphertext according to the keysize, and find the one that
/// has the smallest average Hamming distance between even and odd chunks. That's your keysize.
/// - Chunk the ciphertext into keysize chunks, and then transpose the chunks so you have
/// "ciphertexts" of the first byte of each chunk, then the next, and so on.
/// - Use the single-key method from challenge 3 to determine each byte of the key
#[allow(clippy::type_complexity)]
pub fn break_repeating_key_xor(ciphertext: &[u8]) -> (Vec<u8>, Vec<u8>) {
    // Iterate through various keysizes, chunking the ciphertext into keysize chunks,
    // and find the least average distance between the even and odd chunks
    // That will determine our key size
    let (_distance, keysize) = (2..40).fold(
        (1000f32, 1usize),
        |(last_distance, last_keysize), keysize| {
            // Chunk the ciphertext
            let (odd, even): (Vec<(usize, &[u8])>, Vec<(usize, &[u8])>) = ciphertext
                .chunks(keysize)
                .enumerate()
                .partition(|(i, _chunk)| i % 2 == 0);

            // Compute the average distance
            // This is average distance divided by key length.
            // Since average distance = total distance / number of samples,
            // and number of samples = string length / key length,
            // we end up with average distance = total distance / string length
            let average_distance = odd
                .iter()
                .zip(even)
                .map(|((_, odd_chunk), (_, even_chunk))| hamming_distance(odd_chunk, even_chunk))
                .sum::<usize>() as f32
                / ciphertext.len() as f32;
            if average_distance < last_distance {
                (average_distance, keysize)
            } else {
                (last_distance, last_keysize)
            }
        },
    );

    // Now that we have the key size, chunk the ciphertext in keysize chunks, and then transpose it
    // by taking the first byte of each chunk, then the second, etc. This leaves us with a bunch of
    // single-byte-encrypted ciphertexts.
    let mut nested_vecs: Vec<Vec<u8>> = Vec::new();
    (0..keysize).for_each(|_| nested_vecs.push(Vec::new()));
    let nested_vecs = ciphertext
        .chunks(keysize)
        .fold(nested_vecs, |mut nested_vecs, chunk| {
            chunk
                .iter()
                .enumerate()
                .for_each(|(i, b)| nested_vecs[i].push(*b));

            nested_vecs
        });

    // We find the single-byte key for each transposed ciphertext, and combine each of those into
    // our overall key
    let key = nested_vecs
        .iter()
        .map(|ciphertext| {
            let (key, _score, _plaintext) = find_single_byte_key(ciphertext);
            key
        })
        .collect::<Vec<u8>>();

    // ...and we decrypt
    let plaintext = repeating_key_xor(&key, ciphertext);

    (key, plaintext)
}

#[allow(clippy::clone_double_ref)]
// Break CTR where the same nonce is used
// This basically becomes the Vignere case, where we break the keystream byte by byte
pub fn break_ctr(ciphertexts: &[Vec<u8>]) -> Vec<u8> {
    let mut transposed = vec![];
    for ciphertext in ciphertexts {
        for index in 0..ciphertext.len() {
            if transposed.len() <= index {
                transposed.push(vec![]);
            }
            transposed[index].push(ciphertext[index]);
        }
    }

    let mut keystream = vec![];
    for line in &transposed {
        keystream.push(find_single_byte_key(line).0);
    }

    keystream
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

#[allow(clippy::clone_double_ref)]
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
            &ciphertext[..(block_num + 1) * blocksize],
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

// The following were cribbed from https://jazzy.id.au/2010/09/22/cracking_random_number_generators_part_3.html
// Basically, since we're "undoing" a right shift and xor, we redo the right shift and xor to get
// the original value (original ^ original_shifted = current => original = original_shifted ^
// current). However, we don't _have_ the original value anywhere except the first shift bits, so
// we have to shift that, xor, take those bits, and the next shift bits are now original, so we do
// it again.
pub fn unbitshift_right_xor(v: u64, shift: usize) -> u64 {
    let mut i = 0;
    let mut result: u64 = 0;
    let mut value: u64 = v;
    while i * shift < 32 {
        let partmask: u64 = ((u32::MAX << (32 - shift)) >> (shift * i) as u64).into();
        let part: u64 = value & partmask;
        value ^= part >> shift;
        result |= part;
        i += 1;
    }

    result
}

// Much the same as the previous, except the order of operations are slightly different
// Same concept though
pub fn unbitshift_left_xor(v: u64, shift: usize, mask: u64) -> u64 {
    let mut i = 0;
    let mut result: u64 = 0;
    let mut value: u64 = v;
    while i * shift < 32 {
        let partmask: u64 = ((u32::MAX >> (32 - shift)) << (shift * i) as u64).into();
        let part: u64 = value & partmask;
        value ^= (part << shift) & mask;
        result |= part;
        i += 1;
    }

    result
}

// We "undo" the original temper operations in the reverse order that they were applied
pub fn untemper(value: u32) -> u64 {
    let mut result = unbitshift_right_xor(u64::from(value), L);
    result = unbitshift_left_xor(result, T, C);
    result = unbitshift_left_xor(result, S, B);
    result = unbitshift_right_xor(result, U);

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecb::*;
    use crate::mt19937::{temper, B, C, L, S, T, U};

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

    #[test]
    fn test_unbitshift_left_xor() {
        let mut original: u64 = rand::random::<u32>() as u64;
        let mut value = original ^ ((original << S) & B);

        assert_eq!(original, unbitshift_left_xor(value, S, B));

        original = rand::random::<u32>() as u64;
        value = original ^ ((original << T) & C);

        assert_eq!(original, unbitshift_left_xor(value, T, C));
    }

    #[test]
    fn test_unbitshift_right_xor() {
        let mut original: u64 = rand::random::<u32>() as u64;
        let mut value = original ^ (original >> L);

        assert_eq!(original, unbitshift_right_xor(value, L));

        original = rand::random::<u32>() as u64;
        value = original ^ (original >> U);

        assert_eq!(original, unbitshift_right_xor(value, U));
    }

    #[test]
    fn test_untemper() {
        let original: u64 = rand::random::<u32>() as u64;
        let result: u32 = temper(original);

        let untempered = untemper(result);
        assert_eq!(original, untempered);
    }
}
