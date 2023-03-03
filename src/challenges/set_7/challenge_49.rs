#[cfg(test)]
mod tests {
    use crate::cbc::*;
    use crate::pkcs7::Serialize;
    use crate::util::*;

    struct ClientAndAPI {
        key: Vec<u8>,
        blocksize: usize,
    }

    // Our simulated web API, client and server
    impl ClientAndAPI {
        fn new(blocksize: usize) -> Self {
            Self {
                key: generate_key(blocksize),
                blocksize,
            }
        }

        // Client-created request, first iteration
        // Format: "from=id&to=id&amount=amt"
        fn create_request_v1(&self, from: &str, to: &str, amount: &str) -> Vec<u8> {
            let message = format!("from={}&to={}&amount={}", from, to, amount);
            let iv = generate_iv(self.blocksize);
            let mac = cbc_mac(&self.key, &iv, message.as_bytes(), 16);
            let mut output = message.as_bytes().to_vec();
            output.extend(iv);
            output.extend(mac);

            output
        }

        // Server-checking, first iteration
        fn check_request_v1(&self, request: &[u8]) -> bool {
            let message = &request[0..request.len() - 2 * self.blocksize];
            let iv = &request[message.len()..message.len() + self.blocksize];
            assert_eq!(iv.len(), self.blocksize);
            let mac = &request[request.len() - self.blocksize..];
            assert_eq!(mac.len(), self.blocksize);
            let computed_mac = cbc_mac(&self.key, iv, message, 16);

            mac == computed_mac
        }

        // Client-created request, second iteration
        // Format: "from=id&tx_list=id:amt;id2:amt2"
        fn create_request_v2(&self, from: &str, recipient_amounts: &[(&str, &str)]) -> Vec<u8> {
            let mut message: String = format!("from={}&tx_list=", from);
            let mut first = true;
            for (recipient, amount) in recipient_amounts {
                if first {
                    message.push_str(&format!("{}:{}", recipient, amount));
                    first = false;
                } else {
                    message.push_str(&format!(";{}:{}", recipient, amount));
                }
            }
            let iv = std::iter::repeat(0u8)
                .take(self.blocksize)
                .collect::<Vec<u8>>();
            let mac = cbc_mac(&self.key, &iv, message.as_bytes(), 16);
            let mut output = message.as_bytes().to_vec();
            output.extend(mac);

            output
        }

        // Server-checking, second iteration
        fn check_request_v2(&self, request: &[u8]) -> bool {
            let message = &request[0..request.len() - self.blocksize];
            let mac = &request[request.len() - self.blocksize..];
            assert_eq!(mac.len(), self.blocksize);
            let iv = std::iter::repeat(0u8)
                .take(self.blocksize)
                .collect::<Vec<u8>>();
            let computed_mac = cbc_mac(&self.key, &iv, message, 16);

            mac == computed_mac
        }
    }

    #[test]
    fn challenge_49() {
        let blocksize = 16;

        // Verify that a basic request works
        let client_and_api = ClientAndAPI::new(blocksize);
        let request = client_and_api.create_request_v1("foo", "bar", "1000");
        assert!(client_and_api.check_request_v1(&request));

        // Forge a request by modifying the IV that gets passed along in the request
        let request2 = client_and_api.create_request_v1("foo", "baz", "1000");
        let iv = &request[request.len() - 2 * blocksize..request.len() - blocksize];
        assert_eq!(blocksize, iv.len());
        let forged_iv = xor(
            &xor(&request[..blocksize], &request2[..blocksize]).unwrap(),
            iv,
        )
        .unwrap();
        let mut forged_request = request2[..blocksize].to_vec();
        forged_request.extend_from_slice(&request[blocksize..request.len() - 2 * blocksize]);
        forged_request.extend(forged_iv);
        forged_request.extend_from_slice(&request[request.len() - blocksize..]);
        assert!(client_and_api.check_request_v1(&forged_request));
        assert_eq!(
            "from=foo&to=baz&amount=1000",
            std::str::from_utf8(&forged_request[0..request.len() - 2 * blocksize]).unwrap()
        );

        // New API, IV doesn't get exposed, but the format's changed to allow for multiple
        // transactions from a given account at a time. We forge by extension:
        // - Create our additional message to tack on the end
        // - xor the MAC from the original, valid message with our first block
        // - Make sure our "additions" are in the next block
        // NOTE: This wouldn't work in "real life", because the overall message wouldn't parse,
        // since the block we xored won't, in general, be a valid string
        //
        // Get the valid request and split out the message and mac
        let request = client_and_api.create_request_v2("foo", &[("bar", "200"), ("bee", "200")]);
        assert!(client_and_api.check_request_v2(&request));
        let message = &request[..request.len() - blocksize].to_vec();
        let mac = &request[request.len() - blocksize..];

        // Forge our request
        let request2 = client_and_api.create_request_v2("foo", &[("baz", "1000000")]);

        // XOR the first block with the valid MAC
        let forged_first_block = xor(mac, &request2[..blocksize]).unwrap();

        // This is key, we have to PKCS7 pad the valid message for all this to work
        let mut forged_request = message.pkcs7_serialize(blocksize);
        forged_request.extend(forged_first_block);
        forged_request.extend_from_slice(&request2[blocksize..]);
        assert!(client_and_api.check_request_v2(&forged_request));
    }
}
