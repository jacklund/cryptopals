#[cfg(test)]
mod tests {
    use crate::cbc::cbc_encrypt;
    use crate::ecb::{detect_ecb, ecb_encrypt};
    use crate::tests::ICE_ICE_BABY;
    use crate::util::{generate_iv, generate_key};
    use rand::{self, Rng};

    fn encryption_oracle(key: &[u8], plaintext: &[u8], blocksize: usize) -> (Vec<u8>, bool) {
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

    #[test]
    fn challenge_11() {
        let blocksize = 16;
        for _ in 0..100 {
            let key = generate_key(blocksize);
            let (ciphertext, is_ecb) = encryption_oracle(&key, ICE_ICE_BABY.as_bytes(), blocksize);
            assert_eq!(is_ecb, detect_ecb(&ciphertext, blocksize));
        }
    }
}
