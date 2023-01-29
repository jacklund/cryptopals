#[cfg(test)]
mod tests {
    use crate::dh::DiffieHellman;
    use num_bigint::*;

    #[test]
    fn challenge_33a() {
        let alice = DiffieHellman::new(BigInt::from(37u32), BigInt::from(5u32));
        let bob = DiffieHellman::new(BigInt::from(37u32), BigInt::from(5u32));
        let alice_public = alice.generate_public_key();
        let bob_public = bob.generate_public_key();
        let alice_session = alice.generate_session_key(&bob_public);
        let bob_session = bob.generate_session_key(&alice_public);
        assert_eq!(alice_session, bob_session);
    }

    #[test]
    fn challenge_33b() {
        let alice = DiffieHellman::nist();
        let bob = DiffieHellman::nist();
        let alice_public = alice.generate_public_key();
        let bob_public = bob.generate_public_key();
        let alice_session = alice.generate_session_key(&bob_public);
        let bob_session = bob.generate_session_key(&alice_public);
        assert_eq!(alice_session, bob_session);
    }
}
