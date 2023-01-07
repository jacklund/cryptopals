use crate::{
    pkcs7_pad,
    util::{generate_random_bytes, xor},
};
use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;
use rand::{self, Rng};

pub fn generate_key(blocksize: usize) -> Vec<u8> {
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
            cbc_encrypt(
                key,
                &generate_random_bytes(blocksize),
                &pkcs7_pad(&to_encrypt, blocksize),
                blocksize,
            ),
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

pub fn ecb_encrypt(key: &[u8], plaintext: &[u8], blocksize: usize) -> Vec<u8> {
    let cipher = Aes128::new(GenericArray::from_slice(key));
    pkcs7_pad(&plaintext, blocksize)
        .chunks(blocksize)
        .flat_map(|chunk| {
            let mut block = *GenericArray::from_slice(chunk);
            cipher.encrypt_block(&mut block);
            block.to_vec()
        })
        .collect()
}

// CBC mode using ECB
pub fn cbc_encrypt(key: &[u8], iv: &[u8], plaintext: &[u8], blocksize: usize) -> Vec<u8> {
    let (_, output) = plaintext.chunks(blocksize).fold(
        (iv.to_vec(), Vec::new()),
        |(prev_ciphertext, mut output), chunk| {
            // Xor with previous ciphertext, then encrypt
            let encrypted = ecb_encrypt(key, &xor(&prev_ciphertext, chunk).unwrap(), blocksize);
            output.extend(encrypted.clone());
            (encrypted, output)
        },
    );

    output
}

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

pub fn get_padding_size(datasize: usize, blocksize: usize) -> usize {
    match datasize % blocksize {
        0 => 0,
        value => blocksize - value,
    }
}

// Here we get the prefix size of an encryption function by starting with two blocks of plaintext
// filled with the same character, and then add chars until we get two ciphertext blocks that are
// identical - this means that the prefix is the number of blocks before the identical ciphertext
// blocks, minus the added characters
pub fn get_prefix_size<F: Fn(&[u8]) -> Vec<u8>>(encrypt_fn: &F, blocksize: usize) -> Option<usize> {
    let mut plaintext = std::iter::repeat(b'A')
        .take(blocksize * 2)
        .collect::<Vec<u8>>();
    for padding in 0usize..(blocksize - 1) {
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
            // so take initial size, subtract the prefix stuff, and subtract our padding (minus one
            // since we went over by one)
            return Some(initial_size - (prefix_size + prefix_padding) - (padding - 1));
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

    for pos in 1..test_string_size {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::*;

    #[test]
    fn test_aes_ecb() {
        let plaintext = "THIS IS MY PLAINTEXT";
        let key = "YELLOW SUBMARINE";
        let ciphertext = ecb_encrypt(key.as_bytes(), plaintext.as_bytes(), 16);
        assert_eq!(
            plaintext.as_bytes(),
            pkcs7_unpad(&ecb_decrypt(key.as_bytes(), &ciphertext, 16), 16),
        );
    }

    #[test]
    fn test_aes_cbc() {
        let plaintext = "THIS IS MY PLAINTEXT";
        let key = "YELLOW SUBMARINE";
        let iv = &[0u8; 16];
        let ciphertext = cbc_encrypt(key.as_bytes(), iv, &pkcs7_pad(plaintext.as_bytes(), 16), 16);
        assert_eq!(
            plaintext.as_bytes(),
            pkcs7_unpad(&cbc_decrypt(key.as_bytes(), iv, &ciphertext, 16), 16),
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
