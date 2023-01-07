#[cfg(test)]
mod tests {
    use crate::util::pkcs7_pad;

    #[test]
    fn challenge_9() {
        let plaintext = "YELLOW SUBMARINE";
        assert_eq!(
            "YELLOW SUBMARINE\x04\x04\x04\x04".as_bytes(),
            pkcs7_pad(plaintext.as_bytes(), 20)
        );
        assert_eq!(
            "YELLOW SUBMARINE\x04\x04\x04\x04".as_bytes(),
            pkcs7_pad(plaintext.as_bytes(), 10)
        );
    }
}
