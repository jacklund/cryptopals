use crate::util::unhexify;
use lazy_static::lazy_static;
use num_bigint::*;
use rand;

lazy_static! {
    pub static ref NIST_P: BigInt = BigInt::from_bytes_le(
        Sign::Plus,
        &unhexify(
            "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024\
            e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd\
            3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec\
            6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f\
            24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361\
            c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552\
            bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff\
            fffffffffffff"
        )
        .unwrap()
    );
    pub static ref NIST_G: BigInt = BigInt::from(2u32);
}

pub struct DiffieHellman {
    pub p: BigInt,
    pub g: BigInt,
    pub private_key: BigInt,
}

impl DiffieHellman {
    pub fn new(p: BigInt, g: BigInt) -> Self {
        let mut rng = rand::thread_rng();
        Self {
            p: p.clone(),
            g,
            private_key: rng.gen_bigint_range(&BigInt::from(0u32), &p),
        }
    }

    pub fn nist() -> Self {
        let mut rng = rand::thread_rng();
        Self {
            p: NIST_P.clone(),
            g: NIST_G.clone(),
            private_key: rng.gen_bigint_range(&BigInt::from(0u32), &NIST_P),
        }
    }

    pub fn generate_public_key(&self) -> BigInt {
        self.g.modpow(&self.private_key, &self.p)
    }

    pub fn generate_session_key(&self, public_key: &BigInt) -> BigInt {
        public_key.modpow(&self.private_key, &self.p)
    }
}
