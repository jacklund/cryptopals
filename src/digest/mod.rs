pub mod md4;
pub mod sha1;
pub mod sha256;

use asn1::ObjectIdentifier;

pub trait Digest {
    const BLOCKSIZE: usize;
    const OUTPUT_SIZE: usize;
    const OID: ObjectIdentifier;

    fn new() -> Self;

    fn update(&mut self, message: &[u8]) -> &mut Self;

    fn update_with_length(&mut self, message: &[u8], message_len: usize) -> &mut Self;

    fn digest(&mut self) -> Vec<u8>;
}
