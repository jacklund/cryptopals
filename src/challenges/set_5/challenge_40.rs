#[cfg(test)]
mod tests {
    use crate::rsa::*;
    use num_bigint::*;
    use num_modular::ModularUnaryOps;

    #[test]
    fn challenge_40() {
        let plaintext = "This is my super-secret message".as_bytes();

        // Set the bitlength of the keys. Interestingly, this whole thing doesn't work if the bit
        // length is less than, say, 128
        let bits = 256;

        // Generate 3 public keys
        let (_, pubkey_0) = generate_keypair(bits);
        let (_, pubkey_1) = generate_keypair(bits);
        let (_, pubkey_2) = generate_keypair(bits);

        // Generate 3 ciphertexts from the public keys and the single plaintext
        let c0 = BigUint::from_bytes_be(&encrypt_without_padding(&pubkey_0, plaintext).unwrap());
        let c1 = BigUint::from_bytes_be(&encrypt_without_padding(&pubkey_1, plaintext).unwrap());
        let c2 = BigUint::from_bytes_be(&encrypt_without_padding(&pubkey_2, plaintext).unwrap());

        // Grab the moduli for the public keys
        let n0 = pubkey_0.modulus.to_biguint().unwrap();
        let n1 = pubkey_1.modulus.to_biguint().unwrap();
        let n2 = pubkey_2.modulus.to_biguint().unwrap();

        // Calculate various intermediate values
        let ms0 = &n1 * &n2;
        let ms1 = &n0 * &n2;
        let ms2 = &n0 * &n1;

        let n012 = &n0 * &n1 * &n2;

        let result = c0 * &ms0 * ms0.invm(&n0).unwrap()
            + c1 * &ms1 * ms1.invm(&n1).unwrap()
            + c2 * &ms2 * ms2.invm(&n2).unwrap();

        let decrypted = (result % n012).cbrt().to_bytes_be();
        assert_eq!(plaintext, decrypted);
    }
}
