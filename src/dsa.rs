use crate::digest::Digest;
use crate::util::unhexify;
use lazy_static::lazy_static;
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

lazy_static! {
    pub static ref DEFAULT_P: BigUint = BigUint::from_bytes_be(
        &unhexify(
            "800000000000000089e1855218a0e7dac38136ffafa72eda7\
             859f2171e25e65eac698c1702578b07dc2a1076da241c76c6\
             2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe\
             ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2\
             b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87\
             1a584471bb1"
        )
        .unwrap()
    );
    pub static ref DEFAULT_Q: BigUint =
        BigUint::from_bytes_be(&unhexify("f4f47f05794b256174bba6e9b396a7707e563c5b").unwrap());
    pub static ref DEFAULT_G: BigUint = BigUint::from_bytes_be(
        &unhexify(
            "5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119\
             458fef538b8fa4046c8db53039db620c094c9fa077ef389b5\
             322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047\
             0f5b64c36b625a097f1651fe775323556fe00b3608c887892\
             878480e99041be601a62166ca6894bdd41a7054ec89f756ba\
             9fc95302291"
        )
        .unwrap()
    );
}

#[derive(Debug)]
pub struct DSA {
    p: BigUint,
    q: BigUint,
    g: BigUint,
    check_r: bool,
}

impl Default for DSA {
    fn default() -> Self {
        DSA::new(&DEFAULT_P, &DEFAULT_Q, &DEFAULT_G)
    }
}

impl DSA {
    pub fn new(p: &BigUint, q: &BigUint, g: &BigUint) -> Self {
        Self {
            p: p.clone(),
            q: q.clone(),
            g: g.clone(),
            check_r: true,
        }
    }

    pub fn disable_r_checking(&mut self) {
        self.check_r = false;
    }

    pub fn modulus_size(&self) -> usize {
        ((self.q.bits() + 7) / 8) as usize
    }

    pub fn generate_keypair(&self) -> (PrivateKey, PublicKey) {
        let x = rand::thread_rng().gen_biguint_range(&BigUint::one(), &(&self.q - BigUint::one()));
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
            let inv_k_opt = (&k).invm(&self.q);
            if let Some(inv_k) = inv_k_opt {
                r = self.g.modpow(&k, &self.p) % &self.q;
                s = (inv_k * (&hash + &key.0 * &r)) % &self.q;
                let inv_s_opt = (&s).invm(&self.q);
                if (!self.check_r || r > BigUint::zero())
                    && s > BigUint::zero()
                    && inv_s_opt.is_some()
                {
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

        let w = (&signature.s).invm(&self.q).unwrap();

        let u1 = (hash * &w) % &self.q;
        let u2 = (&signature.r * w) % &self.q;
        let v = ((self.g).modpow(&u1, &self.p) * key.0.modpow(&u2, &self.p) % &self.p) % &self.q;

        v == signature.r
    }

    // Retrieve the public and private keys from the k value
    pub fn get_keys_from_nonce(
        &self,
        &Signature {
            ref r,
            ref s,
            message: _,
            ref hash,
        }: &Signature,
        k: &BigUint,
    ) -> Option<(PrivateKey, PublicKey)> {
        // Because of how we calculate s, s * k has to be > hash for any valid
        // values of k, so we ignore any where this isn't true (also makes the math easier
        if (s * k) < *hash {
            return None;
        }

        // Calculate the keys
        let x = (((s * k) - hash) * r.invm(&self.q).unwrap()) % &self.q;
        let y = self.g.modpow(&x, &self.p);
        Some((PrivateKey::new(x), PublicKey::new(y)))
    }

    pub fn get_keys_from_repeated_nonce(
        &self,
        first: &Signature,
        second: &Signature,
    ) -> Option<(PrivateKey, PublicKey)> {
        let diff_invm = ((&first.s - &second.s) % &self.q).invm(&self.q);
        match diff_invm {
            Some(diff_invm) => {
                let k = ((&first.hash - &second.hash) % &self.q) * diff_invm % &self.q;
                Some(self.get_keys_from_nonce(first, &k).unwrap())
            }
            None => None,
        }
    }
}

pub fn generate_magic_signature() -> Signature {
    let dsa = DSA::new(
        &DEFAULT_P,
        &DEFAULT_Q,
        &(DEFAULT_P.clone() + BigUint::one()),
    );

    let (_private, public) = dsa.generate_keypair();
    let z = BigUint::from(2u32);
    let r = public.value().modpow(&z, &DEFAULT_Q) % DEFAULT_P.clone();
    let s = (&r * z.invm(&DEFAULT_Q).unwrap()) % DEFAULT_Q.clone();

    Signature::new(&r, &s, "", &BigUint::zero())
}
