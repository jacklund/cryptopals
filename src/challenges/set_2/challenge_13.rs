#[cfg(test)]
mod tests {
    use crate::aes::{ecb_decrypt, ecb_encrypt, find_blocksize, generate_key};
    use crate::util::pkcs7_pad;
    use std::collections::HashMap;

    fn profile_for(email: &str) -> String {
        let sanitized = email.replace("&", "").replace("=", "");
        format!("email={}&uid=10&role=user", sanitized)
    }

    fn to_hashmap(profile: &str) -> HashMap<String, String> {
        let kv_list = profile
            .split("&")
            .map(|kv| kv.split("=").collect::<Vec<&str>>())
            .map(|v| (v[0].to_string(), v[1].to_string()));
        HashMap::from_iter(kv_list)
    }

    #[test]
    fn challenge_13() {
        const BLOCKSIZE: usize = 16;
        let key = generate_key(BLOCKSIZE);

        let encrypt_profile_for = |email: &str| {
            ecb_encrypt(
                &key,
                &pkcs7_pad(&profile_for(email).as_bytes(), BLOCKSIZE),
                BLOCKSIZE,
            )
        };
        let decrypt_profile = |ciphertext: &[u8]| {
            to_hashmap(&std::str::from_utf8(&ecb_decrypt(&key, ciphertext, BLOCKSIZE)).unwrap())
        };

        let blocksize = find_blocksize(&|plaintext| {
            encrypt_profile_for(std::str::from_utf8(&plaintext).unwrap())
        })
        .unwrap();
        assert_eq!(16, blocksize);
    }
}
