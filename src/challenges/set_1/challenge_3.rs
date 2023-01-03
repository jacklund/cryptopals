#[cfg(test)]
mod tests {
    use crate::{
        create_histogram, keystream_from_byte, try_xor_key, unhexify, CHAR_LIST_BY_FREQUENCY,
    };

    #[test]
    fn challenge_3() {
        let bytes =
            unhexify("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
                .unwrap();
        let string = std::str::from_utf8(&bytes).unwrap();
        let histogram = create_histogram(string);
        let ciphertext_val = histogram[0].0 as u8;

        // Since p ^ k = c, where p is the plaintext char, k is the key char, and c is the
        // ciphertext char, we can use k = c ^ p. Here, we take the most frequent char in the
        // ciphertext, and xor it with each of the most frequent chars in the English language,
        // and try that as a key. The key that gives us the highest score wins.
        let (key, _score, plaintext) = CHAR_LIST_BY_FREQUENCY.iter().fold(
            (0u8, 0usize, String::new()),
            |(last_key, last_score, last_plaintext), c| {
                let key = (*c as u8) ^ ciphertext_val;
                let (score, plaintext) = try_xor_key(
                    &keystream_from_byte((*c as u8) ^ ciphertext_val, string.len()),
                    string.as_bytes(),
                );
                if score > last_score {
                    (key, score, plaintext)
                } else {
                    (last_key, last_score, last_plaintext)
                }
            },
        );

        assert_eq!("Cooking MC's like a pound of bacon", plaintext);
        assert_eq!('X', key as char);
    }
}
