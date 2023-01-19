#[cfg(test)]
mod tests {
    use crate::digest::md4::*;
    use crate::digest::Digest;

    fn slice_to_u32(slice: &[u8]) -> u32 {
        u32::from_le_bytes(slice.try_into().unwrap())
    }

    #[test]
    fn challenge30() {
        // Generate our original mac
        let original_plaintext =
            "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";
        let key = "SuperSecretKey";
        let mac = md4_mac(&key.as_bytes(), &original_plaintext.as_bytes());

        // Function to validate the mac
        let validate_mac = |message: &[u8], digest| md4_mac(&key.as_bytes(), message) == digest;

        // Split the existing mac into 32-bit chunks
        let mut chunks = mac.chunks(4);
        let a = slice_to_u32(&chunks.next().unwrap());
        let b = slice_to_u32(&chunks.next().unwrap());
        let c = slice_to_u32(&chunks.next().unwrap());
        let d = slice_to_u32(&chunks.next().unwrap());

        // What we're adding to the message
        let new_message = ";admin=true";

        // Generate a forged message with the specified key length
        let generate_forged_message = |keylen| {
            // Figure out the padding for the original message + key
            let glue_padding = get_padding(keylen + original_plaintext.len());

            // Put together the forged message
            let mut forged_message = original_plaintext.as_bytes().to_vec();
            forged_message.extend(glue_padding);
            forged_message.extend(new_message.as_bytes().to_vec());

            // Construct the digest from the state of the original mac, adding the new message, and
            // specifying the updated length. Since we're using the state, it'll start with the
            // original state of the md4 digest, and then add in our extras
            let forged_digest = MD4::new_with_init(a, b, c, d)
                .update_with_length(new_message.as_bytes(), keylen + forged_message.len())
                .digest();
            (forged_message, forged_digest)
        };

        // Try different key lengths
        for keylen in 0..100 {
            let (message, digest) = generate_forged_message(keylen);
            if validate_mac(&message, digest) {
                assert_eq!(key.len(), keylen);
                return;
            }
        }

        assert!(false);
    }
}
