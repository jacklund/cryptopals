#[cfg(test)]
mod tests {
    use crate::aes::ctr;
    use base64;

    #[test]
    fn challenge_18() {
        let ciphertext = base64::decode(
            "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==",
        )
        .unwrap();
        let blocksize = 16;

        let plaintext = ctr("YELLOW SUBMARINE".as_bytes(), 0, &ciphertext, blocksize);
        assert_eq!(
            "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ",
            std::str::from_utf8(&plaintext).unwrap()
        );
        assert_eq!(
            ciphertext,
            ctr("YELLOW SUBMARINE".as_bytes(), 0, &plaintext, blocksize),
        );
    }
}
