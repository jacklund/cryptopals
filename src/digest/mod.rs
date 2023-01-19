pub mod md4;
pub mod sha1;

pub trait Digest {
    const BLOCKSIZE: usize;

    fn new() -> Self;

    fn update(&mut self, message: &[u8]) -> &mut Self;

    fn update_with_length(&mut self, message: &[u8], message_len: usize) -> &mut Self;

    fn digest(&mut self) -> Vec<u8>;
}
