#[cfg(test)]
mod tests {
    use crate::srp::*;
    use num_bigint::*;

    #[test]
    fn challenge_37() {
        let mut server = SRPServer::new();
        server.add_user("foo", "MySuperSecretPassword");
        let mut client = SRPClient::connect(server, false);
        client.use_public_key(BigInt::from(0u32));
        assert!(client.authenticate("foo", ""));

        let mut server = SRPServer::new();
        server.add_user("foo", "MySuperSecretPassword");
        let mut client = SRPClient::connect(server, false);
        client.use_public_key(N.clone());
        assert!(client.authenticate("foo", ""));
    }
}
