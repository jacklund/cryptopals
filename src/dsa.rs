use crate::digest::Digest;
use num::{One, Zero};
use num_bigint::*;
use num_modular::ModularUnaryOps;
use rand;
use std::cmp::min;

#[derive(Debug, PartialEq)]
pub struct PublicKey(BigUint);

impl PublicKey {
    pub fn new(y: BigUint) -> Self {
        Self(y)
    }

    pub fn value(&self) -> BigUint {
        self.0.clone()
    }
}

#[derive(Debug, PartialEq)]
pub struct PrivateKey(BigUint);

impl PrivateKey {
    pub fn new(x: BigUint) -> Self {
        Self(x)
    }

    pub fn value(&self) -> BigUint {
        self.0.clone()
    }
}

#[derive(Clone, Debug)]
pub struct Signature {
    pub r: BigUint,
    pub s: BigUint,
    pub message: String,
    pub hash: BigUint,
}

impl Signature {
    pub fn new(r: &BigUint, s: &BigUint, message: &str, hash: &BigUint) -> Self {
        Self {
            r: r.clone(),
            s: s.clone(),
            message: message.to_string(),
            hash: hash.clone(),
        }
    }
}

#[derive(Debug)]
pub struct DSA {
    p: BigUint,
    q: BigUint,
    g: BigUint,
}

impl DSA {
    pub fn new(p: &BigUint, q: &BigUint, g: &BigUint) -> Self {
        Self {
            p: p.clone(),
            q: q.clone(),
            g: g.clone(),
        }
    }

    pub fn modulus_size(&self) -> usize {
        ((self.q.bits() + 7) / 8) as usize
    }

    pub fn generate_keypair(&self) -> (PrivateKey, PublicKey) {
        let x = rand::thread_rng()
            .gen_biguint_range(&BigUint::one(), &(self.q.clone() - BigUint::one()));
        let y = self.g.modpow(&x, &self.p);
        (PrivateKey(x), PublicKey(y))
    }

    fn hash_message<D>(&self, message: &[u8]) -> BigUint
    where
        D: Digest,
    {
        let mut hasher = D::new();
        hasher.update(message);
        let digest = hasher.digest();
        let hash_len = digest.len();
        let truncated_hash = &digest[..min(self.modulus_size(), hash_len)];
        BigUint::from_bytes_be(truncated_hash)
    }

    pub fn sign<D>(&self, key: &PrivateKey, message: &str) -> Signature
    where
        D: Digest,
    {
        let mut r: BigUint;
        let mut s: BigUint;
        let mut k: BigUint;

        let hash = self.hash_message::<D>(message.as_bytes());
        loop {
            k = rand::thread_rng()
                .gen_biguint_range(&BigUint::one(), &(self.q.clone() - BigUint::one()));
            let inv_k_opt = k.clone().invm(&self.q);
            if let Some(inv_k) = inv_k_opt {
                r = self.g.modpow(&k, &self.p) % self.q.clone();
                s = (inv_k * (hash.clone() + key.0.clone() * r.clone())) % self.q.clone();
                let inv_s_opt = s.clone().invm(&self.q);
                if r > BigUint::zero() && s > BigUint::zero() && inv_s_opt.is_some() {
                    break;
                }
            }
        }

        Signature::new(&r, &s, message, &hash)
    }

    pub fn verify<D>(&self, key: &PublicKey, message: &str, signature: &Signature) -> bool
    where
        D: Digest,
    {
        if signature.r >= self.q || signature.s >= self.q {
            return false;
        }

        let hash = self.hash_message::<D>(message.as_bytes());

        let w = signature.s.clone().invm(&self.q).unwrap();

        let u1 = (hash * w.clone()) % self.q.clone();
        let u2 = (signature.r.clone() * w) % self.q.clone();
        let v = (self.g.clone().modpow(&u1, &self.p) * key.0.clone().modpow(&u2, &self.p)
            % self.p.clone())
            % self.q.clone();

        v == signature.r
    }
}

// Retrieve the public and private keys from the k value
pub fn get_keys_from_k(
    &Signature {
        ref r,
        ref s,
        message: _,
        ref hash,
    }: &Signature,
    k: &BigUint,
    p: &BigUint,
    q: &BigUint,
    g: &BigUint,
) -> Option<(PrivateKey, PublicKey)> {
    // Because of how we calculate s, s * k has to be > hash for any valid
    // values of k, so we ignore any where this isn't true (also makes the math easier
    if (s * k) < *hash {
        return None;
    }

    // Calculate the keys
    let x = (((s * k) - hash) * r.invm(q).unwrap()) % q.clone();
    let y = g.modpow(&x, p);
    Some((PrivateKey::new(x), PublicKey::new(y)))
}
