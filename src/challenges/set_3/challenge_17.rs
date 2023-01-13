#[cfg(test)]
mod tests {
    use crate::cbc::{cbc_decrypt, cbc_encrypt};
    use crate::cracking::decrypt_byte_at_a_time;
    use crate::pkcs7::*;
    use crate::util::{generate_iv, generate_key};
    use base64;
    use rand::{self, Rng};

    const PADDING_ORACLE_STRINGS: [&str; 10] = [
        "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
        "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
        "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
        "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
        "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
        "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
        "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
        "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
        "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
        "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
    ];

    // Black box that generates our ciphertext and IV, and acts as our padding oracle
    struct BlackBox {
        blocksize: usize,
        pub plaintext: Vec<u8>,
        key: Vec<u8>,
    }

    impl BlackBox {
        fn new(blocksize: usize) -> Self {
            // Choose one of the plaintext strings
            let choice = rand::thread_rng().gen_range(0..10);
            let plaintext = base64::decode(PADDING_ORACLE_STRINGS[choice]).unwrap();

            // Encrypt it
            let key = generate_key(blocksize);
            Self {
                blocksize,
                plaintext,
                key,
            }
        }

        fn generate_ciphertext(&self) -> (Vec<u8>, Vec<u8>) {
            let iv = generate_iv(self.blocksize);
            (
                iv.clone(),
                cbc_encrypt(&self.key, &iv, &self.plaintext, self.blocksize),
            )
        }

        fn validate_pkcs7_padding(&self, iv: &[u8], ciphertext: &[u8]) -> bool {
            cbc_decrypt(&self.key, iv, ciphertext, self.blocksize)
                .pkcs7_deserialize(self.blocksize)
                .is_ok()
        }
    }

    #[test]
    fn challenge_17() {
        let blocksize = 16;
        let blackbox = BlackBox::new(blocksize);
        let (iv, ciphertext) = blackbox.generate_ciphertext();

        let solution = decrypt_byte_at_a_time(&iv, &ciphertext, blocksize, &|iv, ciphertext| {
            blackbox.validate_pkcs7_padding(iv, ciphertext)
        });

        assert_eq!(blackbox.plaintext.pkcs7_serialize(blocksize), solution);
    }
}
