use num::One;
use num_bigint::*;
use num_modular::ModularUnaryOps;
use num_prime::RandPrime;
use rand;

#[derive(Debug)]
pub struct RSAKey {
    modulus: BigInt,
    exponent: BigInt,
}

type RSAPublicKey = RSAKey;
type RSAPrivateKey = RSAKey;

impl RSAKey {
    pub fn new(modulus: &BigInt, exponent: &BigInt) -> Self {
        Self {
            modulus: modulus.clone(),
            exponent: exponent.clone(),
        }
    }
}

// Generate a keypair
pub fn generate_keypair(bit_size: usize) -> (RSAPrivateKey, RSAPublicKey) {
    let p_tmp: BigUint = rand::thread_rng().gen_safe_prime(bit_size);
    let q_tmp: BigUint = rand::thread_rng().gen_safe_prime(bit_size);
    let p: BigInt = p_tmp.to_bigint().unwrap();
    let q: BigInt = q_tmp.to_bigint().unwrap();

    let n = p.clone() * q.clone();
    let et = (p - BigInt::one()) * (q - BigInt::one());
    let e = BigUint::from(3u32);
    let d: BigInt = e.clone().invm(&et.to_biguint().unwrap()).unwrap().into();

    (RSAKey::new(&n, &d), RSAKey::new(&n, &e.into()))
}

pub fn encrypt(key: &RSAPublicKey, plaintext: &[u8]) -> Vec<u8> {
    BigInt::from_bytes_le(Sign::Plus, plaintext)
        .modpow(&key.exponent, &key.modulus)
        .to_bytes_le()
        .1
        .to_vec()
}

pub fn decrypt(key: &RSAPrivateKey, ciphertext: &[u8]) -> Vec<u8> {
    BigInt::from_bytes_le(Sign::Plus, ciphertext)
        .modpow(&key.exponent, &key.modulus)
        .to_bytes_le()
        .1
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
