#[cfg(test)]
mod tests {
    use crate::util::{hexify, unhexify, xor};

    #[test]
    fn challenge_2() {
        assert_eq!(
            "746865206b696420646f6e277420706c6179",
            hexify(
                &xor(
                    &unhexify("1c0111001f010100061a024b53535009181c").unwrap(),
                    &unhexify("686974207468652062756c6c277320657965").unwrap()
                )
                .unwrap()
            )
        );
    }
}
