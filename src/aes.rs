use crate::util::xor;
use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;

pub fn aes_ecb_decrypt(key: &[u8], ciphertext: &[u8], blocksize: usize) -> Vec<u8> {
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

pub fn aes_ecb_encrypt(key: &[u8], plaintext: &[u8], blocksize: usize) -> Vec<u8> {
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

// CBC mode using ECB
pub fn aes_cbc_encrypt(key: &[u8], iv: &[u8], plaintext: &[u8], blocksize: usize) -> Vec<u8> {
    let (_, output) = plaintext.chunks(blocksize).fold(
        (iv.to_vec(), Vec::new()),
        |(prev_ciphertext, mut output), chunk| {
            // Xor with previous ciphertext, then encrypt
            let encrypted = aes_ecb_encrypt(key, &xor(&prev_ciphertext, chunk).unwrap(), blocksize);
            output.extend(encrypted.clone());
            (encrypted, output)
        },
    );

    output
}

pub fn aes_cbc_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8], blocksize: usize) -> Vec<u8> {
    let (_, output) = ciphertext.chunks(blocksize).fold(
        (iv.to_vec(), Vec::new()),
        |(prev_ciphertext, mut output), chunk| {
            // Decrypt, then xor with previous ciphertext
            output.extend(&xor(&prev_ciphertext, &aes_ecb_decrypt(key, chunk, blocksize)).unwrap());
            (chunk.to_vec(), output)
        },
    );

    output
}

pub fn detect_aes_ecb(ciphertext: &[u8], blocksize: usize) -> bool {
    let mut chunks = ciphertext.chunks(blocksize).collect::<Vec<&[u8]>>();
    while let Some(chunk) = chunks.pop() {
        if chunks.iter().any(|other| *other == chunk) {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::*;

    #[test]
    fn test_aes_ecb() {
        let plaintext = "THIS IS MY PLAINTEXT";
        let key = "YELLOW SUBMARINE";
        let ciphertext = aes_ecb_encrypt(key.as_bytes(), &pkcs7_pad(plaintext.as_bytes(), 16), 16);
        assert_eq!(
            plaintext.as_bytes(),
            pkcs7_unpad(&aes_ecb_decrypt(key.as_bytes(), &ciphertext, 16), 16),
        );
    }

    #[test]
    fn test_aes_cbc() {
        let plaintext = "THIS IS MY PLAINTEXT";
        let key = "YELLOW SUBMARINE";
        let iv = &[0u8; 16];
        let ciphertext =
            aes_cbc_encrypt(key.as_bytes(), iv, &pkcs7_pad(plaintext.as_bytes(), 16), 16);
        assert_eq!(
            plaintext.as_bytes(),
            pkcs7_unpad(&aes_cbc_decrypt(key.as_bytes(), iv, &ciphertext, 16), 16),
        );
    }
}
