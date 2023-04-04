pub mod challenge_49;
pub mod challenge_50;
pub mod challenge_51;
pub mod challenge_52;
pub mod challenge_53;
pub mod challenge_54;
pub mod challenge_55;

use crate::util::xor;
use aes::{
    cipher::{block_padding::ZeroPadding, generic_array::GenericArray, BlockEncryptMut, KeyInit},
    Aes128,
};

#[allow(dead_code)]
pub const BLOCKSIZE: usize = 16;

// Padding trait, allows us to specify what kind of padding we use with our MD hash
pub trait Padding {
    fn pad(data: &[u8], blocksize: usize) -> Vec<u8>;
}

// No padding, just like it says
struct NoPadding;

impl Padding for NoPadding {
    fn pad(data: &[u8], _blocksize: usize) -> Vec<u8> {
        data.to_vec()
    }
}

// Standard MD padding. Consists of padding a partial block out to full blocksize with a single
// 0x80 byte followed by zero bytes. The next block is the length of the message as a 128-bit int
// value, big-endian
struct MDPadding;

impl Padding for MDPadding {
    // Standard MD-compliant padding - pad with zeroes, then add the length as the last block
    fn pad(data: &[u8], blocksize: usize) -> Vec<u8> {
        // Pad the data out to a multiple of blocksize
        let mut v = if data.len() % blocksize == 0 {
            data.to_vec()
        } else {
            let mut v = data.to_vec();
            v.push(0x80u8);
            v.extend(vec![0u8; blocksize - data.len() - 1]);

            v
        };

        // Add the length
        v.extend((data.len() as u128).to_be_bytes());

        v
    }
}

//
// The MD hash. This just does an AES 128 block cipher, using the IV as an initial key, and the
// intermediate "hash" values as the key for each subsequent block. For "short" hashes (i.e., not a
// full block size), we use the size of the IV as the size of the output hash. We pad the IV out to
// a full block with zeroes, and for each intermediate hash we truncate and zero-fill it so each
// intermediate hash is shortened as well.

#[allow(dead_code)]
// Generate the hash
pub fn md<P>(iv: &[u8], data: &[u8]) -> Vec<u8>
where
    P: Padding,
{
    md_with_states::<P>(iv, data).0
}

#[allow(dead_code)]
// Generate the hash and intermediate hash states
pub fn md_with_states<P>(iv: &[u8], data: &[u8]) -> (Vec<u8>, Vec<Vec<u8>>)
where
    P: Padding,
{
    // Save the intermediate hashes
    let mut hashes = vec![];

    // Use the IV as the starting "hash"
    let mut h = iv.to_vec();

    // Break the data up into BLOCKSIZE blocks
    for block in P::pad(data, BLOCKSIZE).chunks(BLOCKSIZE) {
        // Hash the block, and truncate it to the length of the IV
        h = md_block(&h, block);
        hashes.push(h.clone());
    }

    // Return the truncated hash and the vector of hashes
    (h, hashes)
}

#[allow(dead_code)]
// Hash a single block
pub fn md_block(iv: &[u8], block: &[u8]) -> Vec<u8> {
    // Pad out the IV
    let mut key = iv.to_vec();
    key.extend(vec![0u8; BLOCKSIZE - iv.len()]);

    // Generate the ciphertext, xor it with the IV, and return the truncated hash
    // NOTE: we xor here because of https://twitter.com/_ilchen_/status/1134214918012583936
    let cipher = Aes128::new(GenericArray::from_slice(&key));
    xor(&cipher.encrypt_padded_vec_mut::<ZeroPadding>(block), &key).unwrap()[..iv.len()].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_full_hash_is_iterative() {
        let message = std::iter::repeat_with(rand::random::<u8>)
            .take(3 * BLOCKSIZE)
            .collect::<Vec<u8>>();
        let (hash, hashes) = md_with_states::<NoPadding>(&[0u8; BLOCKSIZE], &message);

        assert_eq!(hash, md::<NoPadding>(&hashes[0], &message[BLOCKSIZE..]),);
        assert_eq!(hash, md::<NoPadding>(&hashes[1], &message[2 * BLOCKSIZE..]),);
    }

    #[test]
    fn test_shortened_hash_is_iterative() {
        let message = std::iter::repeat_with(rand::random::<u8>)
            .take(3 * BLOCKSIZE)
            .collect::<Vec<u8>>();
        let (hash, hashes) = md_with_states::<NoPadding>(&[0u8; 5], &message);

        assert_eq!(
            hash,
            md::<NoPadding>(&hashes[0], &message[BLOCKSIZE..])[..5]
        );
        assert_eq!(
            hash,
            md::<NoPadding>(&hashes[1], &message[2 * BLOCKSIZE..])[..5]
        );
    }
}
