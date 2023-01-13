#[cfg(test)]
mod tests {
    use crate::cracking::break_ctr;
    use crate::ctr::ctr;
    use crate::util::xor;
    use base64;
    use std::fs::File;
    use std::io::{BufRead, BufReader};

    #[test]
    fn challenge_20() {
        let blocksize: usize = 16;
        let plaintexts = BufReader::new(File::open("files/20.txt").unwrap())
            .lines()
            .map(|line| base64::decode(line.unwrap()).unwrap())
            .collect::<Vec<Vec<u8>>>();

        let ciphertexts = plaintexts
            .iter()
            .map(|p| ctr("YELLOW SUBMARINE".as_bytes(), 0, p, blocksize))
            .collect::<Vec<Vec<u8>>>();

        let keystream = break_ctr(&ciphertexts);

        // Note: Just like in 19, there's no good way to validate this, so we just print it out
        for ciphertext in ciphertexts {
            println!(
                "{}",
                std::str::from_utf8(&xor(&keystream[..ciphertext.len()], &ciphertext).unwrap())
                    .unwrap()
            );
        }
    }
}
