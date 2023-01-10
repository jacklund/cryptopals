#[cfg(test)]
mod tests {
    use crate::pkcs7::*;

    #[test]
    fn challenge_9() {
        let plaintext = "YELLOW SUBMARINE";
        assert_eq!(
            "YELLOW SUBMARINE\x04\x04\x04\x04".as_bytes(),
            plaintext.as_bytes().pkcs7_serialize(20)
        );
        assert_eq!(
            "YELLOW SUBMARINE\x04\x04\x04\x04".as_bytes(),
            plaintext.as_bytes().pkcs7_serialize(10)
        );
    }
}
