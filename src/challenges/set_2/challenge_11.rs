#[cfg(test)]
mod tests {
    use crate::aes::{detect_ecb, encryption_oracle, generate_key};
    use crate::tests::ICE_ICE_BABY;

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
