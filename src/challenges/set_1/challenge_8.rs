#[cfg(test)]
mod tests {
    use crate::{detect_aes_ecb, unhexify};
    use std::fs::File;
    use std::io::{BufRead, BufReader};

    #[test]
    fn challenge_8() {
        for line in BufReader::new(File::open("files/8.txt").unwrap()).lines() {
            let ciphertext = unhexify(line.as_ref().unwrap()).unwrap();
            if detect_aes_ecb(&ciphertext, 16) {
                assert_eq!("d880619740a8a19b7840a8a31c810a3d", &line.unwrap()[..32]);
                return;
            }
        }
        assert!(false);
    }
}
