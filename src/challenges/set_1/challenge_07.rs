#[cfg(test)]
mod tests {
    use crate::aes::ecb_decrypt;
    use crate::pkcs7::Deserialize;
    use crate::tests::ICE_ICE_BABY;
    use base64;
    use std::fs::File;
    use std::io::{BufRead, BufReader};

    #[test]
    fn challenge_7() {
        let key = "YELLOW SUBMARINE";
        let ciphertext = BufReader::new(File::open("files/7.txt").unwrap())
            .lines()
            .flat_map(|line| base64::decode(line.unwrap()).unwrap())
            .collect::<Vec<u8>>();
        let plaintext = ecb_decrypt(key.as_bytes(), &ciphertext, 16)
            .pkcs7_deserialize(16)
            .unwrap();

        assert_eq!(
            ICE_ICE_BABY,
            std::str::from_utf8(&plaintext[..ICE_ICE_BABY.len()]).unwrap()
        );
    }
}
