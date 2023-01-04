#[cfg(test)]
mod tests {
    use crate::{find_single_byte_key, unhexify};

    #[test]
    fn challenge_3() {
        let bytes =
            unhexify("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
                .unwrap();
        let (key, _score, plaintext) = find_single_byte_key(&bytes);

        assert_eq!("Cooking MC's like a pound of bacon", plaintext);
        assert_eq!('X', key as char);
    }
}
