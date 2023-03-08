use crate::pkcs7::Serialize;
use crate::util::get_padding_size;
use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;

// Used in Challenges 12 and 14
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

// Decrypt
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

// Encrypt using ECB without the PKCS7 padding
pub fn ecb_encrypt_without_padding(key: &[u8], plaintext: &[u8], blocksize: usize) -> Vec<u8> {
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

// Encrypt using ECB with PKCS7 padding
pub fn ecb_encrypt(key: &[u8], plaintext: &[u8], blocksize: usize) -> Vec<u8> {
    ecb_encrypt_without_padding(key, &plaintext.pkcs7_serialize(blocksize), blocksize)
}

/// Detect AES in ECB mode by encrypting a long string and looking for identical blocks of
/// ciphertext
pub fn detect_ecb(ciphertext: &[u8], blocksize: usize) -> bool {
    let mut chunks = ciphertext.chunks(blocksize).collect::<Vec<&[u8]>>();
    while let Some(chunk) = chunks.pop() {
        if chunks.iter().any(|other| *other == chunk) {
            return true;
        }
    }

    false
}

// Decrypt ECB byte-by-byte by using the padding, pushing a single non-padding byte across the
// block boundary, guessing that, rinse, repeat
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
}
