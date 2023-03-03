#[cfg(test)]
mod tests {
    use crate::digest::sha1::{get_padding, sha1_mac, SHA1};
    use crate::digest::Digest;

    fn slice_to_u32(slice: &[u8]) -> u32 {
        u32::from_be_bytes(slice.try_into().unwrap())
    }

    #[test]
    fn challenge29() {
        let original_plaintext =
            "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";
        let key = "SuperSecretKey";
        let mac = sha1_mac(key.as_bytes(), original_plaintext.as_bytes());

        let validate_mac = |message: &[u8], digest| sha1_mac(key.as_bytes(), message) == digest;

        let mut chunks = mac.chunks(4);
        let a = slice_to_u32(chunks.next().unwrap());
        let b = slice_to_u32(chunks.next().unwrap());
        let c = slice_to_u32(chunks.next().unwrap());
        let d = slice_to_u32(chunks.next().unwrap());
        let e = slice_to_u32(chunks.next().unwrap());

        let new_message = ";admin=true";

        let generate_forged_message = |keylen| {
            let glue_padding = get_padding(keylen + original_plaintext.len());
            let mut forged_message = original_plaintext.as_bytes().to_vec();
            forged_message.extend(glue_padding);
            forged_message.extend(new_message.as_bytes().to_vec());
            let forged_digest = SHA1::new_with_init(a, b, c, d, e)
                .update_with_length(new_message.as_bytes(), keylen + forged_message.len())
                .digest();
            (forged_message, forged_digest)
        };

        for keylen in 0..30 {
            let (message, digest) = generate_forged_message(keylen);
            if validate_mac(&message, digest) {
                assert_eq!(key.len(), keylen);
                return;
            }
        }

        unreachable!()
    }
}
