#[cfg(test)]
mod tests {
    use crate::rsa::*;

    #[test]
    fn challenge_39() {
        let test = "This is my plaintext";
        let (private, public) = generate_keypair(256);
        let ciphertext = encrypt(&public, test.as_bytes());
        assert_eq!(test.as_bytes(), decrypt(&private, &ciphertext));
    }
}
