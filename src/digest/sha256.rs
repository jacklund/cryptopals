use super::Digest as MyDigest;
use asn1::{oid, ObjectIdentifier};
use sha2::{self, Digest};

const SHA256_OID: ObjectIdentifier = oid!(2, 16, 840, 1, 101, 3, 4, 2, 1);

pub struct Sha256 {
    digest: sha2::Sha256,
}

impl MyDigest for Sha256 {
    const BLOCKSIZE: usize = 64;
    const OUTPUT_SIZE: usize = 32;
    const OID: ObjectIdentifier = SHA256_OID;

    fn new() -> Self {
        Self {
            digest: sha2::Sha256::new(),
        }
    }

    fn update(&mut self, message: &[u8]) -> &mut Self {
        self.digest.update(message);
        self
    }

    fn update_with_length(&mut self, _message: &[u8], _message_len: usize) -> &mut Self {
        unimplemented!()
    }

    fn digest(&mut self) -> Vec<u8> {
        self.digest.clone().finalize().to_vec()
    }
}
