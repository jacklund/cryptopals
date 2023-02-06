use num::One;
use num_bigint::*;
use num_modular::ModularUnaryOps;
use num_prime::RandPrime;
use rand;

#[derive(Debug)]
pub struct RSAKey {
    pub modulus: BigUint,
    pub exponent: BigUint,
}

type RSAPublicKey = RSAKey;
type RSAPrivateKey = RSAKey;

impl RSAKey {
    pub fn new(modulus: &BigUint, exponent: &BigUint) -> Self {
        Self {
            modulus: modulus.clone(),
            exponent: exponent.clone(),
        }
    }
}

// Generate a keypair
pub fn generate_keypair(bit_size: usize) -> (RSAPrivateKey, RSAPublicKey) {
    // We loop until we get a p, q pair that will let us generate our d value correctly
    // Tried using "gen_safe_prime()", which worked, but was really slow. This speeds it up
    // considerably
    loop {
        let p: BigUint = rand::thread_rng().gen_prime(bit_size, None);
        let q: BigUint = rand::thread_rng().gen_prime(bit_size, None);

        let n = p.clone() * q.clone();
        let et = (p - BigUint::one()) * (q - BigUint::one());
        let e = BigUint::from(3u32);
        let d: Option<BigUint> = e.clone().invm(&et);

        if d.is_none() {
            continue;
        }

        return (RSAKey::new(&n, &d.unwrap()), RSAKey::new(&n, &e.into()));
    }
}

pub fn encrypt(key: &RSAPublicKey, plaintext: &[u8]) -> Vec<u8> {
    BigUint::from_bytes_le(plaintext)
        .modpow(&key.exponent, &key.modulus)
        .to_bytes_le()
        .to_vec()
}

pub fn decrypt(key: &RSAPrivateKey, ciphertext: &[u8]) -> Vec<u8> {
    BigUint::from_bytes_le(ciphertext)
        .modpow(&key.exponent, &key.modulus)
        .to_bytes_le()
        .to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_modular::ModularUnaryOps;

    #[test]
    fn test_modinv() {
        assert_eq!(
            BigInt::from(1969),
            BigUint::from(42u32)
                .invm(&BigUint::from(2017u32))
                .unwrap()
                .into()
        );
    }
}
