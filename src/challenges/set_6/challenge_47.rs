#[cfg(test)]
mod tests {
    use crate::rsa::{bleichenbacher::*, *};
    use num_bigint::*;

    #[test]
    fn challenge_47() {
        let (private, public) = generate_keypair(256);
        let message = "kick it, CC";
        let ciphertext = encrypt(&public, message.as_bytes()).unwrap();
        assert!(PKCS15Oracle::new(&private).check_padding(&ciphertext));
        let plaintext = decrypt_without_padding(&private, &ciphertext).unwrap();

        let bleichenbacher = Bleichenbacher::new(&private, &public, &ciphertext);

        assert_eq!(BigUint::from_bytes_be(&plaintext), bleichenbacher.attack());
    }
}
