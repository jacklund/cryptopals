#[cfg(test)]
mod tests {
    use crate::{
        cbc::*, dh::DiffieHellman, digest::sha1::SHA1, digest::Digest, util::generate_random_bytes,
    };
    use num_bigint::*;

    const BLOCKSIZE: usize = 16;

    #[test]
    fn challenge_34a() {
        // Use standard NIST params
        let alice = DiffieHellman::nist();

        // Alice "sends" her p, g, and public key to Bob
        let alice_p = alice.p.clone();
        let alice_g = alice.g.clone();
        let alice_public = alice.generate_public_key();

        // Bob uses Alice's p and g values to generate a public key and sends that to Alice
        let bob = DiffieHellman::new(alice_p, alice_g);
        let bob_public = bob.generate_public_key();

        // Alice generates a session key, a CBC key using the SHA1 of the session key, and a random
        // IV
        let alice_session = alice.generate_session_key(&bob_public);
        let alice_cbc_key = &SHA1::new().update(&alice_session.to_bytes_le()).digest()[..BLOCKSIZE];
        let alice_iv = generate_random_bytes(BLOCKSIZE);

        // Alice encrypts her message using the CBC key and IV
        let alice_message = "This is my super-secret message!";
        let mut alice_encrypted = cbc_encrypt(
            &alice_cbc_key,
            &alice_iv,
            alice_message.as_bytes(),
            BLOCKSIZE,
        );

        // She appends the IV to the ciphertext
        alice_encrypted.extend_from_slice(&alice_iv);

        // Bob generates the session key from Alice's public key, and the CBC key
        let bob_session = bob.generate_session_key(&alice_public);
        let bob_cbc_key = &SHA1::new().update(&bob_session.to_bytes_le()).digest()[..BLOCKSIZE];

        // Bob retrieves the IV from the ciphertext
        let bob_iv = &alice_encrypted[alice_encrypted.len() - BLOCKSIZE..];

        // Bob decrypts the message
        let bob_decrypted = cbc_decrypt(
            &bob_cbc_key,
            &bob_iv,
            &alice_encrypted[..alice_encrypted.len() - BLOCKSIZE],
            BLOCKSIZE,
        );

        // Ensure that the message decrypts correctly
        assert_eq!(alice_message.as_bytes(), bob_decrypted,);

        // Bob encrypts the decrypted message, adds the IV, and "sends" it to Alice
        let mut bob_encrypted = cbc_encrypt(&bob_cbc_key, &bob_iv, &bob_decrypted, BLOCKSIZE);
        bob_encrypted.extend_from_slice(&bob_iv);

        // Alice checks that the encrypted data matches
        assert_eq!(alice_encrypted, bob_encrypted);
    }

    #[test]
    fn challenge_34b() {
        // Use standard NIST params
        let alice = DiffieHellman::nist();

        // Alice "sends" her p, g, and public key to Bob
        let alice_p = alice.p.clone();
        let alice_g = alice.g.clone();
        let _alice_public = alice.generate_public_key();

        // Mallory intercepts and instead sends Alice's p value to Bob as Alice's public key
        let alice_public = alice_p.clone();

        // Bob uses Alice's p and g values to generate a public key and sends that to Alice
        let bob = DiffieHellman::new(alice_p.clone(), alice_g);
        let _bob_public = bob.generate_public_key();

        // Mallory intercepts and sends the P value as Bob's public key
        let bob_public = alice_p.clone();

        // Alice generates a session key, a CBC key using the SHA1 of the session key, and a random
        // IV
        let alice_session = alice.generate_session_key(&bob_public);
        let alice_cbc_key = &SHA1::new().update(&alice_session.to_bytes_le()).digest()[..BLOCKSIZE];
        let alice_iv = generate_random_bytes(BLOCKSIZE);

        // Alice's session key is now zero, because p raised to the power of anything mod p is
        // always zero
        assert_eq!(
            std::iter::repeat(0u8)
                .take(alice_session.to_bytes_le().len())
                .collect::<Vec<u8>>(),
            alice_session.to_bytes_le()
        );

        // Alice encrypts her message using the CBC key and IV
        let alice_message = "This is my super-secret message!";
        let mut alice_encrypted = cbc_encrypt(
            &alice_cbc_key,
            &alice_iv,
            alice_message.as_bytes(),
            BLOCKSIZE,
        );

        // She appends the IV to the ciphertext
        alice_encrypted.extend_from_slice(&alice_iv);

        // Bob generates the session key from Alice's public key, and the CBC key
        let bob_session = bob.generate_session_key(&alice_public);
        let bob_cbc_key = &SHA1::new().update(&bob_session.to_bytes_le()).digest()[..BLOCKSIZE];

        // Bob's session key is now also zero
        assert_eq!(
            std::iter::repeat(0u8)
                .take(bob_session.to_bytes_le().len())
                .collect::<Vec<u8>>(),
            bob_session.to_bytes_le()
        );

        // Bob retrieves the IV from the ciphertext
        let bob_iv = &alice_encrypted[alice_encrypted.len() - BLOCKSIZE..];

        // Bob decrypts the message
        let bob_decrypted = cbc_decrypt(
            &bob_cbc_key,
            &bob_iv,
            &alice_encrypted[..alice_encrypted.len() - BLOCKSIZE],
            BLOCKSIZE,
        );

        // Ensure that the message decrypts correctly
        assert_eq!(alice_message.as_bytes(), bob_decrypted,);

        // Bob encrypts the decrypted message, adds the IV, and "sends" it to Alice
        let mut bob_encrypted = cbc_encrypt(&bob_cbc_key, &bob_iv, &bob_decrypted, BLOCKSIZE);
        bob_encrypted.extend_from_slice(&bob_iv);

        // Alice checks that the encrypted data matches
        assert_eq!(alice_encrypted, bob_encrypted);

        // Mallory now decrypts the message, using a zero session key
        let mallory_session = BigUint::from(0u32);
        let mallory_cbc_key =
            &SHA1::new().update(&mallory_session.to_bytes_le()).digest()[..BLOCKSIZE];
        let mallory_iv = &alice_encrypted[alice_encrypted.len() - BLOCKSIZE..];
        let mallory_decrypted = cbc_decrypt(
            &mallory_cbc_key,
            &mallory_iv,
            &alice_encrypted[..alice_encrypted.len() - BLOCKSIZE],
            BLOCKSIZE,
        );

        // Ensure that the message decrypts correctly
        assert_eq!(alice_message.as_bytes(), mallory_decrypted,);
    }
}
