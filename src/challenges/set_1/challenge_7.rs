#[cfg(test)]
mod tests {
    use crate::challenges::set_1::tests::ICE_ICE_BABY;
    use aes::cipher::{generic_array::GenericArray, BlockDecrypt, KeyInit};
    use aes::Aes128;
    use base64;
    use std::fs::File;
    use std::io::{BufRead, BufReader};

    #[test]
    fn challenge_7() {
        let key = "YELLOW SUBMARINE";
        let cipher = Aes128::new(GenericArray::from_slice(key.as_bytes()));
        let ciphertext = BufReader::new(File::open("files/7.txt").unwrap())
            .lines()
            .flat_map(|line| base64::decode(line.unwrap()).unwrap())
            .collect::<Vec<u8>>();
        let plaintext = ciphertext
            .chunks(16)
            .flat_map(|chunk| {
                let mut block = GenericArray::from_slice(chunk).clone();
                cipher.decrypt_block(&mut block);
                block.to_vec()
            })
            .collect::<Vec<u8>>();

        assert_eq!(
            ICE_ICE_BABY,
            std::str::from_utf8(&plaintext[..ICE_ICE_BABY.len()]).unwrap()
        );
    }
}
