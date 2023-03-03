#[cfg(test)]
mod tests {
    use crate::ctr::*;
    use crate::util;
    use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
    use base64;
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use itertools::Itertools;
    use lazy_static::lazy_static;
    use rand::{self, Rng};
    use rayon::prelude::*;
    use std::io::prelude::*;

    // Our Base64 character set
    lazy_static! {
        static ref BASE64_CHARS: Vec<char> = {
            let mut base64_chars = util::NUMBERS_TO_BASE64
                .values()
                .copied()
                .collect::<Vec<char>>();
            base64_chars.push('=');
            base64_chars.sort();
            base64_chars
        };
    }

    type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;

    // Format the payload
    fn format(payload: &str) -> String {
        format!(
            "POST / HTTP/1.1\n\
            Host: hapless.com\n\
            Cookie: sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=\n\
            Content-Length: {}\n\
            {}",
            payload.len(),
            payload
        )
    }

    // Compress the payload
    fn compress(payload: &str) -> Vec<u8> {
        let mut e = ZlibEncoder::new(Vec::new(), Compression::default());
        e.write_all(payload.as_bytes()).unwrap();
        e.finish().unwrap()
    }

    // Encrypt the payload, either with a stream cipher (AES128 in CTR mode) or a block cipher
    // (AES128 in CBC mode). Note, I'm _not_ using my CBC implementation, since it's significantly
    // slower (duh) than the RustCrypto one
    fn encrypt(payload: &[u8], stream: bool) -> Vec<u8> {
        let blocksize = 16;

        // Generate random key each time
        let mut key: [u8; 16] = [0; 16];
        rand::thread_rng().fill(&mut key);

        if stream {
            // Random nonce
            let nonce: u64 = rand::random();
            ctr(&key, nonce, payload, blocksize)
        } else {
            // Random IV
            let mut iv: [u8; 16] = [0; 16];
            rand::thread_rng().fill(&mut iv);

            // Use a real crate here, my impl takes too long
            Aes128CbcEnc::new(&key.into(), &iv.into()).encrypt_padded_vec_mut::<Pkcs7>(payload)
        }
    }

    fn oracle(payload: &str, stream: bool) -> usize {
        encrypt(&compress(&format(payload)), stream).len()
    }

    // My approach:
    // 1. Create a base payload of "Cookie: sessionid="
    // 2. Create a set of payloads by appending each of the possible Base64 characters to it
    // 3. Run each payload through the oracle, and get the subset with the smallest compressed size
    // 4. With that subset, add the next character by going back to step 2. This will be the
    //    product set of my subset and all possible Base64 characters
    // 5. Loop forever. Just kidding. Stop looping when we have a set of solutions all of which
    //    decode to 32 bytes or greater
    // 6. Of that set, find the ones that are exactly 32 bytes. That's our solution set. Hopefully,
    //    there's just one. :-)
    fn compression_ratio_attack(stream: bool) -> String {
        let mut solutions = vec![String::new()];
        loop {
            // Get a list of all possible combinations of the existing solutions combined with a
            // new character, along with it's compression score
            // NOTE: Using rayon here ("par_iter()") to increase parallelism and speed things up
            let mut results = BASE64_CHARS
                .par_iter()
                .map(|c| {
                    solutions.par_iter().map(move |s| {
                        let test = format!("{}{}", s, c);
                        (oracle(&format!("Cookie: sessionid={}", test), stream), test)
                    })
                })
                .flatten()
                .collect::<Vec<(usize, String)>>();

            // Sort them and group them by the compression score. Grab the first group (the ones
            // with the lowest compression score)
            results.sort();
            solutions = results
                .iter()
                .group_by(|(v, _)| v)
                .into_iter()
                .map(|(_, v)| v.map(|(_, s)| s.clone()).collect::<Vec<String>>())
                .collect::<Vec<Vec<String>>>()[0]
                .clone();

            // How do we exit? The session ID is a 32-byte (256-bit) value, so we break when we
            // have a 32-byte solution available (chances are, we'll have multiple)
            if solutions[0].len() % 4 == 0 {
                let value = base64::decode(&solutions[0]).unwrap();
                if value.len() >= 32 {
                    break;
                }
            }
        }

        // Find the one that's exactly 32 bytes
        solutions
            .iter()
            .find(|sol| base64::decode(sol).unwrap().len() == 32)
            .unwrap()
            .clone()
    }

    #[test]
    fn challenge_51() {
        // Using a stream cipher
        assert_eq!(
            "TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=",
            compression_ratio_attack(true)
        );

        // Using a block cipher
        assert_eq!(
            "TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=",
            compression_ratio_attack(false)
        );
    }
}
