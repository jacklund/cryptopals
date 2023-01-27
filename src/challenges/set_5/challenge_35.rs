#[cfg(test)]
mod tests {
    use crate::{
        cbc::*, dh::DiffieHellman, digest::sha1::SHA1, digest::Digest, pkcs7::*,
        util::generate_random_bytes,
    };
    use num_bigint::*;

    const BLOCKSIZE: usize = 16;

    #[test]
    fn challenge_35_g_equals_1() {
        // Use standard NIST params
        let alice = DiffieHellman::nist();

        // Alice "sends" her p, g, and public key to Bob
        let alice_p = alice.p.clone();
        let _alice_g = alice.g.clone();
        let _alice_public = alice.generate_public_key();

        // Mallory intercepts and instead sends 1 as Alice's g value
        let alice_g = BigUint::from(1u32);

        // Mallory also has to send 1 as Alice's public key, or else Bob won't be able to decrypt
        // anything Alice sends
        let alice_public = BigUint::from(1u32);

        // Bob uses Alice's p and g values to generate a public key and sends that to Alice
        let bob = DiffieHellman::new(alice_p.clone(), alice_g);
        let bob_public = bob.generate_public_key();

        // Bob's public key is 1 now, because he used our injected g value of 1
        assert_eq!(BigUint::from(1u32), bob_public);

        // Alice generates a session key, a CBC key using the SHA1 of the session key, and a random
        // IV
        let alice_session = alice.generate_session_key(&bob_public);
        let alice_cbc_key = &SHA1::new().update(&alice_session.to_bytes_le()).digest()[..BLOCKSIZE];
        let alice_iv = generate_random_bytes(BLOCKSIZE);

        // Alice's session key is now one, because Bob's public key is using our injected g value
        // of 1, which means that it's 1 as well
        assert_eq!(BigUint::from(1u32), alice_session);

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
        // Note that Bob's session key is not one, and therefore different than Alice's because her
        // public key isn't based on the g value we injected
        let bob_session = bob.generate_session_key(&alice_public);
        assert_eq!(alice_session, bob_session);
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
        assert_eq!(alice_message.as_bytes(), bob_decrypted);

        // Bob encrypts the decrypted message, adds the IV, and "sends" it to Alice
        let mut bob_encrypted = cbc_encrypt(&bob_cbc_key, &bob_iv, &bob_decrypted, BLOCKSIZE);
        bob_encrypted.extend_from_slice(&bob_iv);

        // Alice checks that the encrypted data matches
        assert_eq!(alice_encrypted, bob_encrypted);

        // Mallory now decrypts the message, using a session key of one
        let mallory_session = BigUint::from(1u32);
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
        assert_eq!(alice_message.as_bytes(), mallory_decrypted);
    }

    #[test]
    fn challenge_35_g_equals_p() {
        // Use standard NIST params
        let alice = DiffieHellman::nist();

        // Alice "sends" her p, g, and public key to Bob
        let alice_p = alice.p.clone();
        let _alice_g = alice.g.clone();
        let _alice_public = alice.generate_public_key();

        // Mallory intercepts and instead sends g == p
        let alice_g = alice_p.clone();

        // Mallory also has to send 0 as Alice's public key, or else Bob won't be able to decrypt
        // anything Alice sends
        let alice_public = BigUint::from(0u32);

        // Bob uses Alice's p and g values to generate a public key and sends that to Alice
        // Bob's public key is now zero, since p ^ a mod p == 0
        let bob = DiffieHellman::new(alice_p.clone(), alice_g);
        let bob_public = bob.generate_public_key();
        assert_eq!(BigUint::from(0u32), bob_public);

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
        assert_eq!(alice_message.as_bytes(), bob_decrypted);

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
        assert_eq!(alice_message.as_bytes(), mallory_decrypted);
    }

    #[test]
    fn challenge_35_g_equals_p_minus_1() {
        // Use standard NIST params
        let alice = DiffieHellman::nist();

        // Alice "sends" her p, g, and public key to Bob
        let alice_p = alice.p.clone();
        let _alice_g = alice.g.clone();
        let _alice_public = alice.generate_public_key();

        // Mallory intercepts Alice's message, and changes g and Alice's public key to p - 1
        // The rub here is that there's really no good way to know whether we should set Alice's
        // public key to 1 or p - 1 - it all depends on what Bob's private key is, and we have no
        // control over that. So, there's a 50/50 chance, roughly, that Bob won't be able to
        // decrypt the message
        let alice_g = alice_p.clone() - BigUint::from(1u32);
        let alice_public = alice_p.clone() - BigUint::from(1u32);

        // Bob uses Alice's p and g values to generate a public key and sends that to Alice
        let bob = DiffieHellman::new(alice_p.clone(), alice_g);
        let bob_public = bob.generate_public_key();

        // Bob's public key is going to be either 1 or p - 1
        if bob_public == BigUint::from(1u32) || bob_public == alice_p.clone() - BigUint::from(1u32)
        {
            assert!(true)
        } else {
            assert!(false)
        };

        // Alice generates a session key, a CBC key using the SHA1 of the session key, and a random
        // IV
        let alice_session = alice.generate_session_key(&bob_public);
        let alice_cbc_key = &SHA1::new().update(&alice_session.to_bytes_le()).digest()[..BLOCKSIZE];
        let alice_iv = generate_random_bytes(BLOCKSIZE);

        // Alice's session key is going to be either 1 or p - 1
        if alice_session == BigUint::from(1u32)
            || alice_session == alice_p.clone() - BigUint::from(1u32)
        {
            assert!(true)
        } else {
            assert!(false)
        };

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

        // We can't assert this - half the time, it won't be true
        // assert_eq!(alice_session, bob_session);

        // Bob retrieves the IV from the ciphertext
        let bob_iv = &alice_encrypted[alice_encrypted.len() - BLOCKSIZE..];

        // Bob decrypts the message
        match cbc_decrypt_without_deserialize(
            &bob_cbc_key,
            &bob_iv,
            &alice_encrypted[..alice_encrypted.len() - BLOCKSIZE],
            BLOCKSIZE,
        )
        .pkcs7_deserialize(BLOCKSIZE)
        {
            Ok(bob_decrypted) => {
                // Ensure that the message decrypts correctly
                assert_eq!(alice_message.as_bytes(), bob_decrypted);

                // Bob encrypts the decrypted message, adds the IV, and "sends" it to Alice
                let mut bob_encrypted =
                    cbc_encrypt(&bob_cbc_key, &bob_iv, &bob_decrypted, BLOCKSIZE);
                bob_encrypted.extend_from_slice(&bob_iv);

                // Alice checks that the encrypted data matches
                assert_eq!(alice_encrypted, bob_encrypted);
            }

            // Half the time, this isn't going to decrypt
            Err(_) => (),
        }

        // Mallory knows that the session key used by Alice to encrypt the message is either 1 or
        // p - 1, so we try both
        for mallory_session in [BigUint::from(1u32), alice_p.clone() - BigUint::from(1u32)] {
            let mallory_cbc_key =
                &SHA1::new().update(&mallory_session.to_bytes_le()).digest()[..BLOCKSIZE];
            let mallory_iv = &alice_encrypted[alice_encrypted.len() - BLOCKSIZE..];
            let mallory_decrypted = cbc_decrypt_without_deserialize(
                &mallory_cbc_key,
                &mallory_iv,
                &alice_encrypted[..alice_encrypted.len() - BLOCKSIZE],
                BLOCKSIZE,
            );
            if let Ok(decrypted) = mallory_decrypted.pkcs7_deserialize(BLOCKSIZE) {
                assert_eq!(alice_message.as_bytes(), decrypted);
                return;
            }
        }

        assert!(false);
    }
}
