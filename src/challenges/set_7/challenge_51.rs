#[cfg(test)]
mod tests {
    use crate::ctr::*;
    use crate::util;
    use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
    use base64;
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use itertools::Itertools;
    use rand::{self, Rng};
    use std::io::prelude::*;

    type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;

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

    fn compress(payload: &str) -> Vec<u8> {
        let mut e = ZlibEncoder::new(Vec::new(), Compression::default());
        e.write_all(payload.as_bytes()).unwrap();
        e.finish().unwrap()
    }

    fn encrypt(payload: &[u8], stream: bool) -> Vec<u8> {
        let blocksize = 16;
        let mut key: [u8; 16] = [0; 16];
        rand::thread_rng().fill(&mut key);
        if stream {
            let nonce: u64 = rand::random();
            ctr(&key, nonce, payload, blocksize)
        } else {
            let mut iv: [u8; 16] = [0; 16];
            rand::thread_rng().fill(&mut iv);
            // Use a real crate here, my impl takes too long
            Aes128CbcEnc::new(&key.into(), &iv.into()).encrypt_padded_vec_mut::<Pkcs7>(&payload)
        }
    }

    fn oracle(payload: &str, stream: bool) -> usize {
        encrypt(&compress(&format(payload)), stream).len()
    }

    fn compression_ratio_attack(stream: bool) -> String {
        // Set up our list of Base64 characters
        let mut base64_chars = util::NUMBERS_TO_BASE64
            .values()
            .map(|c| *c)
            .collect::<Vec<char>>();
        base64_chars.push('=');
        base64_chars.sort();

        // We loop, adding a char each loop iteration
        let mut solutions = vec![String::new()];
        loop {
            // Get a list of all possible combinations of the existing solutions combined with a
            // new character, along with it's compression score
            let mut results = base64_chars
                .iter()
                .map(|c| {
                    solutions.iter().map(move |s| {
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
            .find(|sol| base64::decode(&sol).unwrap().len() == 32)
            .unwrap()
            .clone()
    }

    #[test]
    fn challenge_51() {
        assert_eq!(
            "TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=",
            compression_ratio_attack(true)
        );
        assert_eq!(
            "TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=",
            compression_ratio_attack(false)
        );
    }
}
