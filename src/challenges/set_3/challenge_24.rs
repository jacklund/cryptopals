#[cfg(test)]
mod tests {
    use crate::mt19937;
    use rand::{self, Rng};

    // Basically, we brute-force the key. I limit it to 16 bits because otherwise it takes too
    // long. I think the point here is that the keyspace for even a u32 key is waaaay too small and
    // too easy to brute force.
    #[test]
    fn challenge24() {
        let prefix_len: usize = rand::thread_rng().gen_range(0..100);
        let mut plaintext: Vec<u8> = (0..prefix_len)
            .map(|_| rand::random::<u8>())
            .take(prefix_len)
            .collect();
        plaintext.extend((0..14).map(|_| b'A').take(14).collect::<Vec<u8>>());
        // NOTE: We limit this to u16 because otherwise it takes too long
        let key: u32 = rand::random::<u16>() as u32;
        let ciphertext = mt19937::mt_crypt(key, &plaintext);
        let found = (0..u32::MAX).find(|key| mt19937::mt_crypt(*key, &ciphertext) == plaintext);
        assert_eq!(Some(key), found);
    }
}
