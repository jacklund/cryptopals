#[cfg(test)]
mod tests {
    use crate::digest::sha1::*;
    use crate::dsa::*;
    use num::{One, Zero};
    use num_bigint::*;

    #[test]
    fn challenge_45() {
        // Create DSA with default p and q, but g == 0
        let mut dsa = DSA::new(&DEFAULT_P, &DEFAULT_Q, &BigUint::zero());
        dsa.disable_r_checking();

        // Generate keypair, sign and verify a message
        let (private, public) = dsa.generate_keypair();
        let message = "Hi mom!";
        let signature = dsa.sign::<SHA1>(&private, message);
        assert!(dsa.verify::<SHA1>(&public, message, &signature));

        // Now, generate another keypair, and sign a different message, but verify
        // using the other key and message
        let (private2, _public2) = dsa.generate_keypair();
        let message2 = "Hi dad!";
        let signature = dsa.sign::<SHA1>(&private2, message2);
        // Whoopsie!
        assert!(dsa.verify::<SHA1>(&public, message, &signature));

        // Now, another DSA, this time with g = p + 1
        let dsa = DSA::new(
            &DEFAULT_P,
            &DEFAULT_Q,
            &(DEFAULT_P.clone() + BigUint::one()),
        );
        let (_private, public) = dsa.generate_keypair();

        // Generate our "magic" signature
        let forged = generate_magic_signature();

        // We can verify anything!!
        assert!(dsa.verify::<SHA1>(&public, "Hello, world!", &forged));
        assert!(dsa.verify::<SHA1>(&public, "Goodbye, world!", &forged));
    }
}
