#[cfg(test)]
mod tests {
    use crate::cracking::ETAOIN;
    use crate::ctr::*;
    use crate::ecb::*;
    use crate::pkcs7::Deserialize;
    use crate::tests::ICE_ICE_BABY;
    use base64;
    use rand;
    use std::fs::File;
    use std::io::{BufRead, BufReader};

    #[test]
    fn challenge25() {
        // Read and decrypt the file
        let ciphertext = BufReader::new(File::open("files/25.txt").unwrap())
            .lines()
            .flat_map(|line| base64::decode(line.unwrap()).unwrap())
            .collect::<Vec<u8>>();
        let key = "YELLOW SUBMARINE".as_bytes();
        let blocksize = 16;
        let plaintext_bytes = ecb_decrypt(&key, &ciphertext, blocksize)
            .pkcs7_deserialize(blocksize)
            .unwrap();
        let plaintext = std::str::from_utf8(&plaintext_bytes).unwrap();
        assert_eq!(ICE_ICE_BABY, plaintext);

        // Generate random key and nonce
        let key: Vec<u8> = (0..blocksize).map(|_| rand::random::<u8>()).collect();
        let nonce: u64 = rand::random();

        // Encrypt the plaintext
        let ciphertext = ctr(&key, nonce, &plaintext_bytes, blocksize);

        // "Edit" function
        let edit = |ciphertext: &[u8], offset: usize, new_text: &[u8]| {
            // Take the original ciphertext before the offset
            let mut new_ciphertext = ciphertext[..offset].to_vec();

            // Splice in the encrypted new text
            let keystream_iterator = KeyStreamIterator::new(&key, nonce, blocksize);
            new_ciphertext.extend(
                &new_text
                    .iter()
                    .zip(keystream_iterator.skip(offset))
                    .map(|(p, k)| p ^ k)
                    .take(new_text.len())
                    .collect::<Vec<u8>>(),
            );

            // Add the rest of the original ciphertext
            new_ciphertext.extend(ciphertext[offset + new_text.len()..].to_vec());

            new_ciphertext
        };

        // Test our edit function
        let plaintext_edit = "This is a test";
        let ciphertext_edit = ctr(&key, nonce, plaintext_edit.as_bytes(), blocksize);
        let new_ciphertext = edit(&ciphertext_edit, 10, "toot".as_bytes());
        assert_eq!(
            "This is a toot",
            std::str::from_utf8(&ctr(&key, nonce, &new_ciphertext, blocksize)).unwrap()
        );

        // Crack it
        let solution = (0..ciphertext.len()).fold(vec![], |mut solution, index| {
            match ETAOIN
                .as_bytes()
                .iter()
                .find(|b| edit(&ciphertext, index, &[**b])[index] == ciphertext[index])
            {
                Some(value) => solution.push(*value),
                None => assert!(false),
            };

            solution
        });

        assert_eq!(plaintext, std::str::from_utf8(&solution).unwrap());
    }
}
