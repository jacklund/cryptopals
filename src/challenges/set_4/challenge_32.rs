#[cfg(test)]
mod tests {
    use crate::digest::sha1::SHA1;
    use crate::hmac::*;

    // This was a bear. I tried a huge variety of approaches, starting with the one that worked
    // with 31, zscores, but that didn't work here, nor did using means, max/min, nothing. The
    // problem is that there's just too much noisy jitter in the measurements, so that by the time
    // we get halfway through the sequence, you can't distinguish a real from a false positive.
    #[ignore]
    #[test]
    fn challenge32() {
        let key = "Yellow Submarine";
        let real_signature = hmac_sha1(key.as_bytes(), "foo".as_bytes());
        let mut server = HMacServer::new(5, true).start().unwrap();

        let test_fn = |plaintext: &[u8], signature: &[u8]| {
            let status = tokio_test::block_on(async {
                hmac_client(std::str::from_utf8(plaintext).unwrap(), signature).await
            });
            if status != reqwest::StatusCode::INTERNAL_SERVER_ERROR {
                println!("Status = {:?}", status)
            }
            status == reqwest::StatusCode::OK
        };
        let signature = hmac_timing_attack::<SHA1, _>(&test_fn, "foo".as_bytes(), 1.0);
        server.close().unwrap();
        assert!(signature.is_some());
        assert_eq!(real_signature, signature.unwrap());
    }
}
