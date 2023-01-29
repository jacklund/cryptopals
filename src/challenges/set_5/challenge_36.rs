#[cfg(test)]
mod tests {
    use crate::srp::*;

    #[test]
    fn challenge_36() {
        let mut server = SRPServer::new();
        server.add_user("foo", "MySuperSecretPassword");
        let mut client = SRPClient::new();
        client.connect(server);
        assert!(client.authenticate("foo", "MySuperSecretPassword"));
    }
}
