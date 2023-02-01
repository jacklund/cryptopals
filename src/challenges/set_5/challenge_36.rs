#[cfg(test)]
mod tests {
    use crate::srp::*;

    #[test]
    fn challenge_36() {
        let mut server = SRPServer::new();
        server.add_user("foo", "MySuperSecretPassword");
        let mut client = SRPClient::connect(server, false);
        assert!(client.authenticate("foo", "MySuperSecretPassword"));
    }
}
