#[cfg(test)]
mod tests {
    use crate::rsa::*;
    use num_bigint::*;
    use num_modular::ModularUnaryOps;

    #[test]
    fn challenge_41() {
        let bitsize = 256;
        let plaintext = "This is my super-secret message".as_bytes();
        let (privkey, pubkey) = generate_keypair(bitsize);
        let ciphertext =
            BigUint::from_bytes_be(&encrypt_without_padding(&pubkey, plaintext).unwrap());
        let S = rand::thread_rng().gen_biguint(bitsize as u64);
        let n = pubkey.modulus;
        let e = pubkey.exponent;

        let cprime = (S.modpow(&e, &n) * ciphertext) % &n;
        let pprime = decrypt_without_padding(&privkey, &cprime.to_bytes_be()).unwrap();

        let p = (BigUint::from_bytes_be(&pprime) * S.invm(&n).unwrap()) % n;
        assert_eq!(plaintext, p.to_bytes_be());
    }
}
