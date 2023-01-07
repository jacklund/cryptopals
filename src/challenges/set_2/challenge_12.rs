#[cfg(test)]
mod tests {
    use crate::aes::{
        byte_by_byte_ecb_decrypt, detect_ecb, ecb_encrypt_with_prefix_and_suffix, find_blocksize,
        generate_key, get_prefix_size, get_suffix_size,
    };
    use base64;
    use lazy_static::lazy_static;

    lazy_static! {
        static ref UNKNOWN_STRING: Vec<u8> = base64::decode(
            "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\
         aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
         dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\
         YnkK",
        )
        .unwrap();
        static ref BLOCKSIZE: usize = 16;
    }

    fn encrypt_with_suffix(key: &[u8], plaintext: &[u8]) -> Vec<u8> {
        ecb_encrypt_with_prefix_and_suffix(key, plaintext, &[], &UNKNOWN_STRING, *BLOCKSIZE)
    }

    #[test]
    fn challenge_12() {
        let key = generate_key(*BLOCKSIZE);
        let encrypt_fn = |plaintext: &[u8]| encrypt_with_suffix(&key, plaintext);
        let blocksize = find_blocksize(&encrypt_fn).unwrap();
        assert_eq!(*BLOCKSIZE, blocksize);

        let is_ecb = detect_ecb(
            &encrypt_with_suffix(
                &key,
                &std::iter::repeat(b'A')
                    .take(2 * blocksize)
                    .collect::<Vec<u8>>(),
            ),
            blocksize,
        );
        assert!(is_ecb);

        let prefix_size = get_prefix_size(&encrypt_fn, blocksize).unwrap();
        assert_eq!(0, prefix_size);

        let suffix_size = get_suffix_size(&encrypt_fn, prefix_size, blocksize).unwrap();
        assert_eq!(UNKNOWN_STRING.len(), suffix_size);

        let solution = byte_by_byte_ecb_decrypt(&encrypt_fn, prefix_size, suffix_size, blocksize);
        assert!(solution.is_some());
        assert_eq!(
            "Rollin' in my 5.0\n\
            With my rag-top down so my hair can blow\n\
            The girlies on standby waving just to say hi\n\
            Did you stop? No, I just drove by\n",
            std::str::from_utf8(&solution.unwrap()).unwrap()
        );
    }
}
