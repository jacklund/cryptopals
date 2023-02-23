#[cfg(test)]
mod tests {
    use crate::pkcs7::*;
    use crate::util::*;
    use aes::{
        cipher::{block_padding::Pkcs7, generic_array::GenericArray, BlockEncryptMut, KeyInit},
        Aes128,
    };
    use rand::{self, Rng};
    use std::collections::HashMap;

    // Our hash
    struct MD {
        h_bytes: usize,
        collisions: Vec<(Vec<u8>, Vec<u8>)>,
        pub num_hashes: usize,
    }

    impl MD {
        // Hash with initial H size
        fn new(h_bytes: usize) -> Self {
            Self {
                h_bytes,
                collisions: vec![],
                num_hashes: 0,
            }
        }

        // Generate the hash
        fn md(&mut self, data: &[u8]) -> Vec<u8> {
            let blocksize = 16;

            let h_init = vec![0u8; self.h_bytes];
            let mut h = h_init.clone();
            for block in data.pkcs7_serialize(blocksize).chunks(blocksize) {
                h.extend(vec![0u8; blocksize - h.len()]);
                let cipher = Aes128::new(GenericArray::from_slice(&h));
                // NOTE: we xor here, see https://twitter.com/_ilchen_/status/1134214918012583936
                h = xor(
                    &cipher.encrypt_padded_vec_mut::<Pkcs7>(&block)[..h_init.len()].to_vec(),
                    &h[..h_init.len()],
                )
                .unwrap();
            }

            self.num_hashes += 1;
            h
        }

        // Find 2^n collisions
        fn find_collisions(&mut self, n: u32) -> Vec<(Vec<u8>, Vec<u8>)> {
            // Keep track of the hashes
            let mut hashes = HashMap::<Vec<u8>, Vec<u8>>::new();

            // Generate random messages
            for message in rand::thread_rng()
                .sample_iter::<u64, rand::distributions::Standard>(rand::distributions::Standard)
            {
                let bytes = message.to_be_bytes();
                let hash = self.md(&bytes);

                // Find those collisions
                if hashes.contains_key(&hash) {
                    self.collisions
                        .push((bytes.to_vec(), hashes.get(&hash).unwrap().clone()));
                    if self.collisions.len() >= 2usize.pow(n) {
                        break;
                    }
                } else {
                    hashes.insert(hash, bytes.to_vec());
                }
            }

            self.collisions.clone()
        }
    }

    #[test]
    fn challenge_52() {
        let mut f = MD::new(3);
        let mut g = MD::new(4);
        let both_collisions = f
            .find_collisions(8)
            .iter()
            .filter(|(message1, message2)| g.md(message1) == g.md(message2))
            .map(|(m1, m2)| (m1.clone(), m2.clone()))
            .collect::<Vec<(Vec<u8>, Vec<u8>)>>();

        // Honestly, not sure what to assert here
        println!("total hashes = {}", f.num_hashes);
        println!("collisions = {}", both_collisions.len());
    }
}
