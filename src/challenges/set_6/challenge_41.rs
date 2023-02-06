#[cfg(test)]
mod tests {
    use crate::rsa::*;
    use num_bigint::*;
    use num_modular::ModularUnaryOps;
    use rand;

    #[test]
    fn challenge_41() {
        let plaintext = "This is my super-secret message".as_bytes();
        let (privkey, pubkey) = generate_keypair(128);
        let ciphertext = BigUint::from_bytes_le(&encrypt(&pubkey, plaintext));
        let S = rand::thread_rng().gen_biguint(128);
        let n = pubkey.modulus;
        let e = pubkey.exponent;

        let cprime = (S.modpow(&e, &n) * ciphertext) % n.clone();
        let pprime = decrypt(&privkey, &cprime.to_bytes_le());

        let p = (BigUint::from_bytes_le(&pprime) * S.invm(&n).unwrap()) % n;
        assert_eq!(plaintext, p.to_bytes_le());
    }
}
