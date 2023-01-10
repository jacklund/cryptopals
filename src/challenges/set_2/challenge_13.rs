#[cfg(test)]
mod tests {
    use crate::aes::{ecb_decrypt, ecb_encrypt, find_blocksize, generate_key};
    use crate::pkcs7::*;
    use crate::util::get_padding_size;
    use std::collections::HashMap;

    fn profile_for(email: &str) -> String {
        let sanitized = email.replace("&", "").replace("=", "");
        format!("email={}&uid=10&role=user", sanitized)
    }

    fn to_hashmap(profile: &str) -> HashMap<String, String> {
        let kv_list = profile
            .split("&")
            .take(3)
            .map(|kv| kv.split("=").collect::<Vec<&str>>())
            .map(|v| (v[0].to_string(), v[1].to_string()));
        HashMap::from_iter(kv_list)
    }

    #[test]
    fn challenge_13() {
        const PREFIX: usize = "email=".len();
        const SUFFIX: usize = "&uid=10&role=".len();
        const BLOCKSIZE: usize = 16;
        let key = generate_key(BLOCKSIZE);

        let encrypt_profile_for = |email: &str| {
            ecb_encrypt(
                &key,
                &profile_for(email).as_bytes().pkcs7_serialize(BLOCKSIZE),
                BLOCKSIZE,
            )
        };
        let decrypt_profile = |ciphertext: &[u8]| {
            let decrypted = ecb_decrypt(&key, ciphertext, BLOCKSIZE);
            String::from_utf8(decrypted).unwrap()
        };

        let blocksize = find_blocksize(&|plaintext| {
            encrypt_profile_for(std::str::from_utf8(&plaintext).unwrap())
        })
        .unwrap();
        assert_eq!(16, blocksize);

        // Create a fake email which pushes the "admin" part past a block boundary
        let mut fake_email = std::iter::repeat('A')
            .take(blocksize - PREFIX)
            .collect::<String>();
        fake_email.push_str("admin");
        let encrypted = encrypt_profile_for(&fake_email);

        // Grab the block containing "admin..."
        let admin_part = &encrypted[blocksize..2 * blocksize];

        // Now create an email which pushes the "role=" just at a block boundary
        let padding = get_padding_size(PREFIX + SUFFIX, blocksize);
        let fake_email = std::iter::repeat('A').take(padding).collect::<String>();
        let mut encrypted = encrypt_profile_for(&fake_email);

        // Truncate the last block and add our admin block
        encrypted.resize(encrypted.len() - blocksize, 0u8);
        encrypted.extend(admin_part);

        // Decrypt and test
        let decrypted = decrypt_profile(&encrypted);
        assert_eq!("admin", to_hashmap(&decrypted).get("role").unwrap());
    }
}
