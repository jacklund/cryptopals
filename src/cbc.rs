use crate::ecb::{ecb_decrypt, ecb_encrypt_without_padding};
use crate::pkcs7::{Deserialize, Serialize};
use crate::util::xor;

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
pub fn cbc_decrypt_without_deserialize(
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
    blocksize: usize,
) -> Vec<u8> {
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

// CBC mode using ECB
// p = cp ^ d(c)
// where c is the ciphertext, cp is the previous ciphertext (or iv), p is the plaintext and d is
// the decryption function
pub fn cbc_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8], blocksize: usize) -> Vec<u8> {
    cbc_decrypt_without_deserialize(key, iv, ciphertext, blocksize)
        .pkcs7_deserialize(blocksize)
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::*;

    #[test]
    fn test_aes_cbc() {
        let plaintext = "THIS IS MY PLAINTEXT";
        let key = "YELLOW SUBMARINE";
        let iv = generate_iv(16);
        let ciphertext = cbc_encrypt(key.as_bytes(), &iv, plaintext.as_bytes(), 16);
        assert_eq!(
            plaintext.as_bytes(),
            &cbc_decrypt(key.as_bytes(), &iv, &ciphertext, 16)
        );
    }
}
