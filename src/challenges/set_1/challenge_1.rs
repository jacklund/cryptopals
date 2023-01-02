#[cfg(test)]
mod tests {
    use crate::{to_base64, unhexify};

    #[test]
    fn challenge_1() {
        let value = unhexify("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d").unwrap();
        assert_eq!(
            "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",
            to_base64(&value)
        );
    }
}
