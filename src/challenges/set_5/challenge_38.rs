#[cfg(test)]
mod tests {
    use crate::srp::*;
    use crate::util;
    use hmac::{Hmac, Mac};
    use num_bigint::*;
    use sha2::{Digest, Sha256};

    type HmacSha256 = Hmac<Sha256>;

    // From https://en.wikipedia.org/wiki/List_of_the_most_common_passwords#NordPass
    const BAD_PASSWORD_LIST: [&str; 20] = [
        "123456",
        "123456789",
        "12345",
        "qwerty",
        "password",
        "12345678",
        "111111",
        "123123",
        "1234567890",
        "1234567",
        "qwerty123",
        "000000",
        "1q2w3e",
        "aa12345678",
        "abc123",
        "password1",
        "1234",
        "qwertyuiop",
        "123321",
        "password123",
    ];

    struct SRPMitmServer {
        server: SRPServer,
    }

    impl SRPMitmServer {
        fn new(server: SRPServer) -> Self {
            Self { server }
        }
    }

    impl SRPSessionServer<SRPMitmSession> for SRPMitmServer {
        fn start_session(&mut self, user: &str, public_key: &BigInt) -> SRPMitmSession {
            SRPMitmSession::new(self.server.start_session(user, public_key), public_key)
        }
    }

    struct SRPMitmSession {
        session: SRPServerSession,
        password: Option<String>,
        client_public_key: BigInt,
        u: BigInt,
    }

    impl SRPMitmSession {
        fn new(session: SRPServerSession, public_key: &BigInt) -> Self {
            Self {
                session,
                password: None,
                client_public_key: public_key.clone(),
                u: BigInt::from(0u32),
            }
        }

        fn crack_password(&mut self, client_hmac: &[u8]) {
            // Dictionary attack
            for password in BAD_PASSWORD_LIST {
                // We calculate our x based on what we passed to the client
                let x = hash_to_int(&[], password.as_bytes());

                // This takes some 'splainin:
                // The simplified client calculates S as:
                //   B ^ (a + u * x) % N
                // However, we provide it B = g, so this becomes:
                //   ((g ^ a) % N * (g ^ (u * x)) % N) % N
                // which equals:
                //   (A * (g ^ (u * x)) % N) % N
                let S = (self.client_public_key.clone()
                    * g.clone().modpow(&(self.u.clone() * x), &N))
                .modpow(&BigInt::from(1u32), &N);
                let k = Sha256::digest(util::get_bytes(&S));
                let hmac = HmacSha256::new_from_slice(k.as_slice())
                    .unwrap()
                    .finalize()
                    .into_bytes();
                if hmac.as_slice() == client_hmac {
                    self.password = Some(password.to_string());
                    break;
                }
            }
        }

        fn get_password(&self) -> Option<String> {
            self.password.clone()
        }
    }

    impl SRPSession for SRPMitmSession {
        fn start_authentication(&self) -> (Vec<u8>, BigInt) {
            // Send salt == &[], and B == g
            (Vec::new(), g.clone())
        }

        fn get_u(&mut self) -> BigInt {
            let u = self.session.get_u();
            self.u = u;
            self.u.clone()
        }

        fn authenticate(&mut self, hmac_of_shared_key: &[u8]) -> bool {
            let result = self.session.authenticate(hmac_of_shared_key);
            self.crack_password(hmac_of_shared_key);
            result
        }
    }

    #[test]
    fn challenge_38_test_simplified() {
        let mut real_server = SRPServer::simplified();
        real_server.add_user("foo", "password");
        let mut client = SRPClient::connect(real_server, true);
        assert!(client.authenticate("foo", "password"));
    }

    #[test]
    fn challenge_38_crack_password() {
        let mut real_server = SRPServer::simplified();
        real_server.add_user("foo", "password");
        let mitm_server = SRPMitmServer::new(real_server);
        let mut client = SRPClient::connect(mitm_server, true);
        client.authenticate("foo", "password");
        let cracked_password = client.get_session().get_password();
        assert!(cracked_password.is_some());
        assert_eq!("password", cracked_password.unwrap());
    }
}
