#[cfg(test)]
mod tests {
    use crate::aes::{cbc_decrypt, cbc_encrypt, generate_iv, generate_key};
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

        cbc_encrypt(key, &iv, string.as_bytes(), blocksize)
    }

    // Decrypt our ciphertext
    fn decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8], blocksize: usize) -> Vec<u8> {
        cbc_decrypt(key, iv, ciphertext, blocksize)
    }

    // Decode our ciphertext
    fn decode(decrypted: &[u8]) -> HashMap<String, String> {
        let plaintext = unsafe { std::str::from_utf8_unchecked(&decrypted) };
        HashMap::from_iter(
            plaintext
                .split(';')
                .map(|v| v.split('=').collect::<Vec<&str>>())
                .map(|v| (v[0].to_string(), v[1].to_string()))
                .collect::<Vec<(String, String)>>(),
        )
    }

    // Are we admin?
    fn is_admin(map: HashMap<String, String>) -> bool {
        match map.get("admin") {
            Some(value) => std::str::FromStr::from_str(value).unwrap(),
            None => false,
        }
    }

    #[test]
    fn challenge_16() {
        let blocksize = 16;
        let key = generate_key(blocksize);
        let iv = generate_iv(blocksize);

        // Make sure we can't just set the values
        let encrypted = encode_and_encrypt(&key, &iv, ";admin=true", blocksize);
        let decrypted = decrypt(&key, &iv, &encrypted, blocksize);
        let values = decode(&decrypted);
        assert!(!is_admin(values));

        // We use an allowed value (?) to substitute for ; and =
        let mut encrypted = encode_and_encrypt(&key, &iv, "?admin?true", blocksize);

        // Our first ? is at byte 32, so to mess with it, we have to mess with byte 16, the block
        // before. Since, in CBC mode, the ciphertext from the block before will be xor-ed with the
        // block you're decrypting, this is equivalent to bit-flipping that block.
        // This will totally munge the block you flip the bit on, but hopefully this won't matter.

        // We want '?' => ';', so this is 0x3F => 0x3b, which means we need to flip bit 3
        encrypted[16] ^= 4;

        // We want '?' => '=', so this is 0x3F => 0x3D, so we flip the second bit
        encrypted[22] ^= 2;

        // To test, we now decrypt it, convert it to a hashmap, and test if it worked
        let decrypted = decrypt(&key, &iv, &encrypted, blocksize);
        let values = decode(&decrypted);
        assert!(is_admin(values));
    }
}
