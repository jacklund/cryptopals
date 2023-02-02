use crate::util;
use hmac::{Hmac, Mac};
use lazy_static::lazy_static;
use num::Zero;
use num_bigint::*;
use rand;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

type HmacSha256 = Hmac<Sha256>;

// Generate an HMAC from a key and a value
pub fn generate_hmac(key: &[u8], value: &[u8]) -> Vec<u8> {
    let mut hmac = HmacSha256::new_from_slice(key).unwrap();
    hmac.update(value);
    hmac.finalize().into_bytes().to_vec()
}

// Convert a SHA256 hash to a BigInt
pub fn hash_to_int(a: &[u8], b: &[u8]) -> BigInt {
    let mut hasher = Sha256::new();
    hasher.update(a);
    hasher.update(b);
    let xh = hasher.finalize();
    BigInt::from_bytes_le(Sign::Plus, &xh.to_vec())
}

const k: u32 = 3;

lazy_static! {
    // This is just DH NIST_P
    pub static ref N: BigInt = BigInt::from_bytes_le(
        Sign::Plus,
        &util::unhexify(
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
    pub static ref g: BigInt = BigInt::from(2u32);
}

// Trait for a server that creates a session
// Need this abstraction for the MITM server in challenge 38
pub trait SRPSessionServer<T>
where
    T: SRPSession,
{
    fn start_session(&mut self, user: &str, public_key: &BigInt) -> T;
}

// Trait for the session
pub trait SRPSession {
    fn start_authentication(&self) -> (Vec<u8>, BigInt);

    // Only for simplified
    fn get_u(&mut self) -> BigInt;

    fn authenticate(&mut self, hmac_of_shared_key: &[u8]) -> bool;
}

// NOTE: Rather than creating an actual "server" that listens on a port, etc, I simulate it here
// using a server struct and a client struct, where the client class calls into the server class to
// "connect", gets the session object, and then does the authentication dance with that object.
pub struct SRPServer {
    users: HashMap<String, String>,
    simplified: bool,
}

// Clippy made me do it
impl Default for SRPServer {
    fn default() -> Self {
        Self::new()
    }
}

// SRP Server
impl SRPServer {
    // "Standard" server
    pub fn new() -> Self {
        Self {
            users: HashMap::new(),
            simplified: false,
        }
    }

    // Server for "simplified" SRP
    pub fn simplified() -> Self {
        Self {
            users: HashMap::new(),
            simplified: true,
        }
    }

    pub fn add_user(&mut self, user: &str, password: &str) {
        self.users.insert(user.to_string(), password.to_string());
    }
}

impl SRPSessionServer<SRPServerSession> for SRPServer {
    fn start_session(&mut self, user: &str, A: &BigInt) -> SRPServerSession {
        self.users
            .get(user)
            .map(|password| SRPServerSession::new(password, A, self.simplified))
            .unwrap()
    }
}

// Generate our v value
fn generate_verifier(salt: &[u8], password: &str) -> BigInt {
    let x = hash_to_int(salt, password.as_bytes());
    g.modpow(&x, &N)
}

// Server session for SRP
pub struct SRPServerSession {
    salt: Vec<u8>,
    b: BigInt,
    B: BigInt,
    A: BigInt,
    verifier: BigInt,
    u: BigInt,
}

// Create the server session by passing in the password, client public key, and whether we're using
// the standard or simplified SRP
impl SRPServerSession {
    pub fn new(password: &str, A: &BigInt, simplified: bool) -> Self {
        // Generate a random private key
        let b = rand::thread_rng().gen_bigint_range(&BigInt::zero(), &N);

        let salt = rand::random::<u32>().to_le_bytes();

        let verifier = generate_verifier(&salt, password);

        // Generate a public key from the password DH key and the private key
        let B = if simplified {
            // Simplified SRP - server public key doesn't depend on password
            //  B = g ^ b % N
            g.modpow(&b, &N)
        } else {
            // Standard SRP
            //  B = k * v + g ^ b % N
            k * verifier.clone() + g.modpow(&b, &N)
        };

        let u = if simplified {
            // Generate our u value as a random number for simplified SRP
            // This needs to be positive, because it'll be used as an exponent
            rand::thread_rng().gen_biguint(16).to_bigint().unwrap()
        } else {
            // Hash the client and server public keys together for "standard" SRP
            hash_to_int(&util::get_bytes(A), &util::get_bytes(&B))
        };

        Self {
            salt: salt.to_vec(),
            b,
            B,
            A: A.clone(),
            verifier,
            u,
        }
    }
}

impl SRPSession for SRPServerSession {
    fn start_authentication(&self) -> (Vec<u8>, BigInt) {
        (self.salt.clone(), self.B.clone())
    }

    // In simplified SRP, the client gets the u value from the server along with the salt and B.
    // Client will call this separately in simplified SRP after calling start_authentication()
    fn get_u(&mut self) -> BigInt {
        self.u.clone()
    }

    // Authenticate by generating the HMAC of the shared key, and comparing
    fn authenticate(&mut self, hmac_of_shared_key: &[u8]) -> bool {
        //  S = (A * (v ^ u % N)) ^ b % N
        let S = (self.A.clone() * self.verifier.modpow(&self.u, &N)).modpow(&self.b, &N);

        // Shared key, which is the SHA256 hash of S
        let K = Sha256::digest(util::get_bytes(&S));

        // Generate the HMAC from K and the salt
        let hmac = generate_hmac(K.as_slice(), self.salt.as_slice());

        // Compare the HMACs
        hmac.as_slice() == hmac_of_shared_key
    }
}

pub struct SRPClient<T, U>
where
    T: SRPSessionServer<U>,
    U: SRPSession,
{
    server: T,
    session: Option<U>,
    A: Option<BigInt>,
    simplified: bool,
}

impl<T, U> SRPClient<T, U>
where
    T: SRPSessionServer<U>,
    U: SRPSession,
{
    pub fn use_public_key(&mut self, public_key: BigInt) {
        self.A = Some(public_key);
    }

    pub fn connect(server: T, simplified: bool) -> Self {
        Self {
            server,
            session: None,
            A: None,
            simplified,
        }
    }

    pub fn get_session(&mut self) -> U {
        self.session.take().unwrap()
    }

    pub fn authenticate(&mut self, user: &str, password: &str) -> bool {
        // Generate a random private key
        let a = rand::thread_rng().gen_bigint_range(&BigInt::zero(), &N);

        // Generate a DH public key from the private key
        let A = match self.A.clone() {
            Some(A) => A,
            None => g.modpow(&a, &N),
        };

        // Send our username and public key
        let mut session = self.server.start_session(user, &A);

        // Get the salt and the server's public key
        let (salt, B) = session.start_authentication();

        // Get our u value
        let u = if self.simplified {
            // In simplified SRP, the server passes this to us along with the salt and B. Here, we
            // have to do a separate call to get it
            session.get_u()
        } else {
            // Hash both public keys together
            hash_to_int(&util::get_bytes(&A), &util::get_bytes(&B))
        };

        // Hash the salt and the password together
        let x = hash_to_int(&salt, password.as_bytes());

        // Generate S
        let S = match self.A.clone() {
            // In the case where we send back a bogus value for A, we have to set S to zero for the
            // auth to happen
            Some(_) => BigInt::zero(),

            None => {
                if self.simplified {
                    // Simplified, S = B ^ (a + ux) % N
                    B.modpow(&(a + u * x), &N)
                } else {
                    // Standard, S = (B - k * g ^ x) ^ (a + ux) % N
                    (B - k * g.clone().modpow(&x, &N)).modpow(&(a + u * x), &N)
                }
            }
        };

        // Hash S to get the shared key
        let K = Sha256::digest(util::get_bytes(&S));

        // Hmac the salt with the shared key
        let hmac = generate_hmac(K.as_slice(), salt.as_slice());

        let result = session.authenticate(&hmac);
        self.session = Some(session);
        result
    }
}
