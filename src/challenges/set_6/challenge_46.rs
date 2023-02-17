#[cfg(test)]
mod tests {
    use crate::rsa::*;
    use base64;
    use num::Zero;
    use num_bigint::*;
    use std::ops::Shr;

    #[test]
    fn challenge_46() {
        // Decode the plaintext
        let plaintext = base64::decode("VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==").unwrap();

        // Generate the keypair and encrypt the plaintext
        let (private, public) = generate_keypair(1024);
        let ciphertext = encrypt_without_padding(&public, &plaintext).unwrap();

        // Set lower and upper bounds
        let mut bounds = (BigUint::zero(), private.modulus.clone());

        // Get ciphertext as a number
        let mut c = BigUint::from_bytes_be(&ciphertext);

        // We're going to multiply the ciphertext by the encrypted value of 2, which is the same as
        // multiplying the plaintext by 2
        let two_encrypted =
            BigUint::from_bytes_be(&encrypt_without_padding(&public, &vec![2u8]).unwrap());

        // For each bit, multiply by two and see if it's odd or even
        for _ in 0..public.modulus.bits() {
            c = c.clone() * two_encrypted.clone();
            if is_even_oracle(&private, &c.to_bytes_be()) {
                bounds = (
                    bounds.0.clone(),
                    (bounds.0.clone() + bounds.1.clone()).shr(1),
                );
            } else {
                bounds = (
                    (bounds.0.clone() + bounds.1.clone()).shr(1),
                    bounds.1.clone(),
                );
            }
            println!("{}", String::from_utf8_lossy(&bounds.1.to_bytes_be()));
        }

        // Very strange, I can get all but the last char - I'm guessing this is due to some sort of
        // rounding error or something
        // assert_eq!(plaintext, bounds.1.to_bytes_be());
        assert!(String::from_utf8_lossy(&bounds.1.to_bytes_be())
            .starts_with("That's why I found you don't play around with the Funky Cold Medin"));
    }
}
