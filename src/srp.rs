use crate::dh;
use hmac::{Hmac, Mac};
use num_bigint::*;
use rand;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

type HmacSha256 = Hmac<Sha256>;

fn hash_to_int(a: &[u8], b: &[u8]) -> BigUint {
    let mut hasher = Sha256::new();
    hasher.update(a);
    hasher.update(b);
    let xh = hasher.finalize();
    BigUint::from_bytes_le(&xh)
}

const K: u32 = 3;

pub struct SRPServer {
    users: HashMap<String, String>,
}

impl SRPServer {
    pub fn new() -> Self {
        Self {
            users: HashMap::new(),
        }
    }

    pub fn add_user(&mut self, user: &str, password: &str) {
        self.users.insert(user.to_string(), password.to_string());
    }

    pub fn start_session(&self, user: &str, public_key: &BigUint) -> Option<SRPServerSession> {
        match self.users.get(user) {
            Some(password) => Some(SRPServerSession::new(password, public_key)),
            None => None,
        }
    }
}

fn generate_verifier(salt: u32, password: &str) -> BigUint {
    let x = hash_to_int(&salt.to_le_bytes(), password.as_bytes());
    dh::NIST_G.modpow(&x, &dh::NIST_P)
}

pub struct SRPServerSession {
    salt: u32,
    private_key: BigUint,
    public_key: BigUint,
    client_public_key: BigUint,
    verifier: BigUint,
    u: BigUint,
}

impl SRPServerSession {
    pub fn new(password: &str, client_public_key: &BigUint) -> Self {
        // Generate a random private key
        let private_key = rand::thread_rng().gen_biguint_range(&BigUint::from(0u32), &dh::NIST_P);

        let salt = rand::random::<u32>();

        let verifier = generate_verifier(salt, password);

        // Generate a public key from the password DH key and the private key
        let public_key = K * verifier.clone() + dh::NIST_G.modpow(&private_key, &dh::NIST_P);

        let u = hash_to_int(&client_public_key.to_bytes_le(), &public_key.to_bytes_le());

        Self {
            salt,
            private_key,
            public_key,
            client_public_key: client_public_key.clone(),
            verifier,
            u,
        }
    }

    pub fn start_authentication(&self) -> (u32, BigUint) {
        (self.salt, self.public_key.clone())
    }

    pub fn authenticate(&self, hmac_of_shared_key: &[u8]) -> bool {
        let s = (self.client_public_key.clone() * self.verifier.modpow(&self.u, &dh::NIST_P))
            .modpow(&self.private_key, &dh::NIST_P);
        let shared_key = Sha256::digest(&s.to_bytes_le());
        let hmac = HmacSha256::new_from_slice(shared_key.as_slice())
            .unwrap()
            .finalize()
            .into_bytes();

        hmac.as_slice() == hmac_of_shared_key
    }
}

pub struct SRPClient {
    server: Option<SRPServer>,
}

impl SRPClient {
    pub fn new() -> Self {
        Self { server: None }
    }

    pub fn connect(&mut self, server: SRPServer) {
        self.server = Some(server);
    }

    pub fn authenticate(&mut self, user: &str, password: &str) -> bool {
        // Generate a random private key
        let private_key = rand::thread_rng().gen_biguint_range(&BigUint::from(0u32), &dh::NIST_P);

        // Generate a DH public key from the private key
        let public_key = dh::NIST_G.modpow(&private_key, &dh::NIST_P);

        let session = self
            .server
            .as_ref()
            .unwrap()
            .start_session(user, &public_key)
            .unwrap();

        // Send our public key, and get the salt and the server's public key
        let (salt, server_public_key) = session.start_authentication();

        // Hash both public keys together
        let u = hash_to_int(&public_key.to_bytes_le(), &server_public_key.to_bytes_le());

        // Hash the salt and the password together
        let x = hash_to_int(&salt.to_le_bytes(), password.as_bytes());

        // Generate a session key
        let s = (server_public_key - K * dh::NIST_G.clone().modpow(&x, &dh::NIST_P))
            .modpow(&(private_key + u * x), &dh::NIST_P);

        // Hash the session key
        let shared_key = Sha256::digest(&s.to_bytes_le());

        // Hmac the salt with the session key
        let hmac = HmacSha256::new_from_slice(shared_key.as_slice())
            .unwrap()
            .finalize()
            .into_bytes();

        session.authenticate(&hmac.as_slice())
    }
}
