#[cfg(test)]
mod tests {
    use crate::aes::{detect_aes_ecb, encryption_oracle};
    use crate::tests::ICE_ICE_BABY;

    #[test]
    fn challenge_11() {
        for _ in 0..100 {
            let (ciphertext, is_ecb) = encryption_oracle(ICE_ICE_BABY.as_bytes());
            assert_eq!(is_ecb, detect_aes_ecb(&ciphertext, 16));
        }
    }
}
