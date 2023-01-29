#[cfg(test)]
mod tests {
    use crate::{dh, srp::*};
    use num_bigint::*;

    #[test]
    fn challenge_37() {
        let mut server = SRPServer::new();
        server.add_user("foo", "MySuperSecretPassword");
        let mut client = SRPClient::new();
        client.use_public_key(BigInt::from(0u32));
        client.connect(server);
        assert!(client.authenticate("foo", ""));

        let mut server = SRPServer::new();
        server.add_user("foo", "MySuperSecretPassword");
        let mut client = SRPClient::new();
        client.use_public_key(dh::NIST_P.clone());
        client.connect(server);
        assert!(client.authenticate("foo", ""));
    }
}
