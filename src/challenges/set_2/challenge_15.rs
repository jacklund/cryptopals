#[cfg(test)]
mod tests {
    use crate::util::pkcs7_unpad;

    #[test]
    fn challenge_15() {
        let value = "ICE ICE BABY".as_bytes();
        let good_padding = "ICE ICE BABY\x04\x04\x04\x04".as_bytes().to_vec();
        let bad_padding_1 = "ICE ICE BABY\x05\x05\x05\x05".as_bytes();
        let bad_padding_2 = "ICE ICE BABY\x01\x02\x03\x04".as_bytes();

        match pkcs7_unpad(&good_padding, 16) {
            Ok(result) => assert_eq!(value, result),
            Err(_) => assert!(false),
        };

        match pkcs7_unpad(&bad_padding_1, 16) {
            Ok(_) => assert!(false),
            Err(_) => assert!(true),
        };

        match pkcs7_unpad(&bad_padding_2, 16) {
            Ok(_) => assert!(false),
            Err(_) => assert!(true),
        };
    }
}
