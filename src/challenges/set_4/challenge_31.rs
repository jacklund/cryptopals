#[cfg(test)]
mod tests {
    use crate::digest::sha1::SHA1;
    use crate::hmac::*;

    #[test]
    fn challenge31() {
        let key = "Yellow Submarine";
        let real_signature = hmac_sha1(key.as_bytes(), "foo".as_bytes());
        let mut server = HMacServer::new(50, true).start().unwrap();

        let test_fn = |plaintext: &[u8], signature: &[u8]| {
            let status = tokio_test::block_on(async {
                hmac_client(std::str::from_utf8(plaintext).unwrap(), signature).await
            });
            if status != reqwest::StatusCode::INTERNAL_SERVER_ERROR {
                println!("Status = {:?}", status);
            }
            status == reqwest::StatusCode::OK
        };
        let signature = hmac_timing_attack::<SHA1, _>(&test_fn, "foo".as_bytes(), 3.0);
        server.close().unwrap();
        assert!(signature.is_some());
        assert_eq!(real_signature, signature.unwrap());
    }
}
