#[cfg(test)]
mod tests {
    use crate::tests::ICE_ICE_BABY;
    use crate::{aes::ecb_decrypt, util::pkcs7_unpad};
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
        let plaintext = pkcs7_unpad(&ecb_decrypt(key.as_bytes(), &ciphertext, 16), 16).unwrap();

        assert_eq!(
            ICE_ICE_BABY,
            std::str::from_utf8(&plaintext[..ICE_ICE_BABY.len()]).unwrap()
        );
    }
}
