#[cfg(test)]
mod tests {
    use crate::cbc::{cbc_decrypt_without_deserialize, cbc_encrypt};
    use crate::util::generate_key;
    use std::collections::HashMap;

    // Encode our string, making sure to escape ; and = (and space, just for fun)
    fn encode(value: &str) -> String {
        let mut output = String::new();
        for ch in value.chars() {
            match ch {
                ';' => output.push_str("%3B"),
                '=' => output.push_str("%3D"),
                ' ' => output.push_str("%20"),
                _ => output.push(ch),
            }
        }

        output
    }

    // Encode our string with prefix and suffix
    fn encode_and_encrypt(key: &[u8], iv: &[u8], value: &str, blocksize: usize) -> Vec<u8> {
        let prefix = "comment1=cooking%20MCs;userdata=";
        let suffix = ";comment2=%20like%20a%20pound%20of%20bacon";
        let mut string = prefix.to_string();
        string.push_str(&encode(value));
        string.push_str(suffix);

        cbc_encrypt(key, iv, string.as_bytes(), blocksize)
    }

    // Decrypt our ciphertext
    fn decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8], blocksize: usize) -> Vec<u8> {
        cbc_decrypt_without_deserialize(key, iv, ciphertext, blocksize)
    }

    #[derive(Debug)]
    struct ASCIIError {
        plaintext: Vec<u8>,
    }

    // Decode our ciphertext
    fn decode(decrypted: &[u8]) -> Result<HashMap<String, String>, ASCIIError> {
        if decrypted.iter().any(|b| *b > 127) {
            Err(ASCIIError {
                plaintext: decrypted.to_vec(),
            })
        } else {
            let plaintext = unsafe { std::str::from_utf8_unchecked(decrypted) };
            Ok(HashMap::from_iter(
                plaintext
                    .split(';')
                    .map(|v| v.split('=').collect::<Vec<&str>>())
                    .map(|v| (v[0].to_string(), v[1].to_string()))
                    .collect::<Vec<(String, String)>>(),
            ))
        }
    }

    // Are we admin?
    fn is_admin(map: HashMap<String, String>) -> bool {
        match map.get("admin") {
            Some(value) => std::str::FromStr::from_str(value).unwrap(),
            None => false,
        }
    }

    // So, this took some time for me to grok
    // Basically, we generate some ciphertext, and then change it
    // If we generate (c1, c2, c3), we change it to (c1, 0, c1) where 0 is an all-zero block
    // Then we get back (p1, p2, p3) and the key is p1 ^ p3.
    // The reason this works is that p1 = D(K, c1) ^ K (since we're using the key for the IV)
    // and p3 will end up being D(K, c1) ^ 0, since we're re-sending c1 as c3, and sending 0 as the
    // second block.
    // So, p1 ^ p3 = D(K, c1) ^ K ^ D(K, c1) ^ 0 = K
    #[test]
    fn challenge_27() {
        let blocksize = 16;
        let key = generate_key(blocksize);
        let iv = key.clone();

        // Make sure we can't just set the values
        let encrypted = encode_and_encrypt(&key, &iv, ";admin=true", blocksize);
        let decrypted = decrypt(&key, &iv, &encrypted, blocksize);
        let values = decode(&decrypted).unwrap();
        assert!(!is_admin(values));

        // Encrypt a bogus value
        let encrypted = encode_and_encrypt(&key, &iv, "foo", blocksize);

        // Create our bogus ciphertext
        // Copy block 1
        let mut bogus = encrypted[..blocksize].to_vec();

        // Block 2 becomes all zeroes
        bogus.extend(std::iter::repeat(0u8).take(blocksize).collect::<Vec<u8>>());

        // Block 3 is block 1 again
        bogus.extend(encrypted[..blocksize].to_vec());

        match decode(&decrypt(&key, &iv, &bogus, blocksize)) {
            Err(ASCIIError { plaintext }) => {
                assert_eq!(
                    key,
                    plaintext[..blocksize]
                        .iter()
                        .zip(plaintext[blocksize * 2..].iter())
                        .map(|(a, b)| a ^ b)
                        .collect::<Vec<u8>>()
                );
            }
            Ok(_) => panic!(),
        }
    }
}
