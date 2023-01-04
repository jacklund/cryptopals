#[cfg(test)]
mod tests {
    use crate::break_repeating_key_xor;
    use crate::tests::ICE_ICE_BABY;
    use base64;
    use std::fs::File;
    use std::io::{BufRead, BufReader};

    #[test]
    fn challenge_6() {
        let ciphertext = BufReader::new(File::open("files/6.txt").unwrap())
            .lines()
            .flat_map(|line| base64::decode(line.unwrap()).unwrap())
            .collect::<Vec<u8>>();

        let (key, plaintext) = break_repeating_key_xor(&ciphertext);
        assert_eq!(
            "Terminator X: Bring the noise",
            std::str::from_utf8(&key).unwrap()
        );
        assert_eq!(ICE_ICE_BABY, std::str::from_utf8(&plaintext).unwrap());
    }
}
