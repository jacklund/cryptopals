use super::Digest;
use asn1::{oid, ObjectIdentifier};

const MD4_OID: ObjectIdentifier = oid!(1, 2, 840, 113549, 2, 3);

// Default initialization constants
pub const A: u32 = u32::from_be(0x01234567);
pub const B: u32 = u32::from_be(0x89abcdef);
pub const C: u32 = u32::from_be(0xfedcba98);
pub const D: u32 = u32::from_be(0x76543210);
pub const G: u32 = u32::from_le(0x5a827999);
pub const H: u32 = u32::from_le(0x6ed9eba1);

// Auxillary functions used to generate the hashes
pub fn f(x: &u32, y: &u32, z: &u32) -> u32 {
    (x & y) | (!x & z)
}

pub fn g(x: &u32, y: &u32, z: &u32) -> u32 {
    (x & y) | (x & z) | (y & z)
}

pub fn h(x: &u32, y: &u32, z: &u32) -> u32 {
    x ^ y ^ z
}

fn get_padding_size(message_len: usize) -> usize {
    match message_len % 64 {
        size @ 0..=55 => 56 - size,
        size => 56 + (64 - size),
    }
}

/// Return the padding for the given message length
pub fn get_padding(message_len: usize) -> Vec<u8> {
    let padding_size = get_padding_size(message_len);

    let mut padding = vec![0x80u8];
    padding.extend(std::iter::repeat(0u8).take(padding_size - 1));

    // Add the message len (in bits) as the final 8 bytes, taking it to an even multiple of 64
    // bytes
    padding.extend(((message_len * 8) as u64).to_le_bytes());

    padding
}

/// Convenience function to generate an MD4 hash of the given message
pub fn md4(message: &[u8]) -> Vec<u8> {
    MD4::new().update(message).digest()
}

/// Convenience function to generate an MD4 MAC of the given message with the given key
pub fn md4_mac(key: &[u8], message: &[u8]) -> Vec<u8> {
    MD4::new().mac(key, message)
}

/// MD4 hash
pub struct MD4 {
    state: [u32; 4],
}

impl MD4 {
    /// Initialize MD4 with customized values
    pub fn new_with_init(a: u32, b: u32, c: u32, d: u32) -> Self {
        Self {
            state: [a, b, c, d],
        }
    }

    /// Generate an MD4 MAC
    pub fn mac(&mut self, key: &[u8], message: &[u8]) -> Vec<u8> {
        let mut value = key.to_vec();
        value.extend(message);
        self.update(&value).digest()
    }

    pub fn round_1(&mut self, block: &[u32]) {
        let shifts = [3, 7, 11, 19];
        let state_indices = [0, 3, 2, 1];
        for block_index in 0..=15 {
            let state_index = state_indices[block_index % 4];
            let shift = shifts[block_index % 4];
            self.state[state_index] = self.apply_f(state_index, block[block_index], shift);
        }
    }

    pub fn round_2(&mut self, block: &[u32]) {
        let shifts = [3, 5, 9, 13];
        let state_indices = [0, 3, 2, 1];
        for index in 0..=15 {
            let block_index = if index < 15 { (index * 4) % 15 } else { 15 };
            let state_index = state_indices[index % 4];
            let shift = shifts[index % 4];
            self.state[state_index] = self.apply_g(state_index, block[block_index], shift);
        }
    }

    pub fn round_3(&mut self, block: &[u32]) {
        let block_indices = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15];
        let shifts = [3, 9, 11, 15];
        let state_indices = [0, 3, 2, 1];
        for index in 0..=15 {
            let block_index = block_indices[index];
            let state_index = state_indices[index % 4];
            let shift = shifts[index % 4];
            self.state[state_index] = self.apply_h(state_index, block[block_index], shift);
        }
    }

    fn apply_f(&mut self, index: usize, value: u32, shift: u32) -> u32 {
        // Syntactic sugar
        let a = &self.state[index];
        let b = &self.state[(index + 1) % self.state.len()];
        let c = &self.state[(index + 2) % self.state.len()];
        let d = &self.state[(index + 3) % self.state.len()];

        a.wrapping_add(f(b, c, d))
            .wrapping_add(value)
            .rotate_left(shift)
    }

    fn apply_g(&mut self, index: usize, value: u32, shift: u32) -> u32 {
        // Syntactic sugar
        let a = &self.state[index];
        let b = &self.state[(index + 1) % self.state.len()];
        let c = &self.state[(index + 2) % self.state.len()];
        let d = &self.state[(index + 3) % self.state.len()];

        a.wrapping_add(g(b, c, d))
            .wrapping_add(value)
            .wrapping_add(G)
            .rotate_left(shift)
    }

    fn apply_h(&mut self, index: usize, value: u32, shift: u32) -> u32 {
        // Syntactic sugar
        let a = &self.state[index];
        let b = &self.state[(index + 1) % self.state.len()];
        let c = &self.state[(index + 2) % self.state.len()];
        let d = &self.state[(index + 3) % self.state.len()];

        a.wrapping_add(h(b, c, d))
            .wrapping_add(value)
            .wrapping_add(H)
            .rotate_left(shift)
    }
}

/// Digest trait implementation for MD4
impl Digest for MD4 {
    const BLOCKSIZE: usize = 64;
    const OUTPUT_SIZE: usize = 16;
    const OID: ObjectIdentifier = MD4_OID;

    /// Generate an MD4 struct with the default initial values
    fn new() -> Self {
        Self::new_with_init(A, B, C, D)
    }

    /// Update with a message
    fn update(&mut self, message: &[u8]) -> &mut Self {
        self.update_with_length(message, message.len())
    }

    /// Update with a message of a given length
    fn update_with_length(&mut self, message: &[u8], message_len: usize) -> &mut Self {
        // Pad message out so that len % 64 = 56
        let mut output = message.to_vec();
        output.extend(get_padding(message_len));

        // Split into 32-bit words
        let words = output
            .chunks(4)
            .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
            .collect::<Vec<u32>>();

        for block in words.chunks(16) {
            // Rounds
            self.round_1(block);
            self.round_2(block);
            self.round_3(block);

            // Add the original value back
            self.state[0] = self.state[0].wrapping_add(A);
            self.state[1] = self.state[1].wrapping_add(B);
            self.state[2] = self.state[2].wrapping_add(C);
            self.state[3] = self.state[3].wrapping_add(D);
        }

        self
    }

    /// Generate the digest
    fn digest(&mut self) -> Vec<u8> {
        // Generate the output
        let mut out = vec![];
        out.extend(self.state[0].to_le_bytes().to_vec());
        out.extend(self.state[1].to_le_bytes().to_vec());
        out.extend(self.state[2].to_le_bytes().to_vec());
        out.extend(self.state[3].to_le_bytes().to_vec());

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::unhexify;
    use rand::{self, Rng};

    #[test]
    fn test_get_padding_size() {
        for _ in 0..20 {
            let message = std::iter::repeat(b'A')
                .take(rand::thread_rng().gen_range(5..200))
                .collect::<Vec<u8>>();
            let padding_size = get_padding_size(message.len());
            assert_eq!(56, (padding_size + message.len()) % 64);
        }
        let message = std::iter::repeat(b'A').take(56).collect::<Vec<u8>>();
        let padding_size = get_padding_size(message.len());
        assert_eq!(120, padding_size + message.len());
    }

    #[test]
    fn test_md4() {
        let message = "love1234";
        let hash = md4(message.as_bytes());
        assert_eq!(unhexify("84fbc7744cb2ff163b684e0aedcdb8da").unwrap(), hash);

        let message = "Terminator X: Bring the noise";
        let hash = md4(message.as_bytes());
        assert_eq!(unhexify("851cea118e0e18927aa39066cb4b1590").unwrap(), hash);
    }
}
