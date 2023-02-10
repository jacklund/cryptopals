use super::Digest;
use asn1::{oid, ObjectIdentifier};

const MD4_OID: ObjectIdentifier = oid!(1, 2, 840, 113549, 2, 3);

const A: u32 = u32::from_be(0x01234567);
const B: u32 = u32::from_be(0x89abcdef);
const C: u32 = u32::from_be(0xfedcba98);
const D: u32 = u32::from_be(0x76543210);

fn f(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (!x & z)
}

fn g(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (x & z) | (y & z)
}

fn h(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

fn get_padding_size(message_len: usize) -> usize {
    match message_len % 64 {
        size @ 0..=55 => 56 - size,
        size => 56 + (64 - size),
    }
}

pub fn get_padding(message_len: usize) -> Vec<u8> {
    let padding_size = get_padding_size(message_len);

    let mut padding = vec![0x80u8];
    padding.extend(std::iter::repeat(0u8).take(padding_size - 1));

    // Add the message len (in bits) as the final 8 bytes, taking it to an even multiple of 64
    // bytes
    padding.extend(((message_len * 8) as u64).to_le_bytes());

    padding
}

pub fn md4(message: &[u8]) -> Vec<u8> {
    MD4::new().update(message).digest()
}

pub fn md4_mac(key: &[u8], message: &[u8]) -> Vec<u8> {
    MD4::new().mac(key, message)
}

pub struct MD4 {
    a: u32,
    b: u32,
    c: u32,
    d: u32,
}

fn operation_1(a: u32, b: u32, c: u32, d: u32, value: u32, shift: u32) -> u32 {
    a.wrapping_add(f(b, c, d))
        .wrapping_add(value)
        .rotate_left(shift)
}

fn operation_2(a: u32, b: u32, c: u32, d: u32, value: u32, shift: u32) -> u32 {
    a.wrapping_add(g(b, c, d))
        .wrapping_add(value)
        .wrapping_add(0x5a827999u32)
        .rotate_left(shift)
}

fn operation_3(a: u32, b: u32, c: u32, d: u32, value: u32, shift: u32) -> u32 {
    a.wrapping_add(h(b, c, d))
        .wrapping_add(value)
        .wrapping_add(0x6ed9eba1u32)
        .rotate_left(shift)
}

impl MD4 {
    pub fn new_with_init(a: u32, b: u32, c: u32, d: u32) -> Self {
        Self { a, b, c, d }
    }

    pub fn mac(&mut self, key: &[u8], message: &[u8]) -> Vec<u8> {
        let mut value = key.to_vec();
        value.extend(message);
        self.update(&value).digest()
    }

    fn round_1(&mut self, block: &[u32]) {
        self.a = operation_1(self.a, self.b, self.c, self.d, block[0], 3);
        self.d = operation_1(self.d, self.a, self.b, self.c, block[1], 7);
        self.c = operation_1(self.c, self.d, self.a, self.b, block[2], 11);
        self.b = operation_1(self.b, self.c, self.d, self.a, block[3], 19);
        self.a = operation_1(self.a, self.b, self.c, self.d, block[4], 3);
        self.d = operation_1(self.d, self.a, self.b, self.c, block[5], 7);
        self.c = operation_1(self.c, self.d, self.a, self.b, block[6], 11);
        self.b = operation_1(self.b, self.c, self.d, self.a, block[7], 19);
        self.a = operation_1(self.a, self.b, self.c, self.d, block[8], 3);
        self.d = operation_1(self.d, self.a, self.b, self.c, block[9], 7);
        self.c = operation_1(self.c, self.d, self.a, self.b, block[10], 11);
        self.b = operation_1(self.b, self.c, self.d, self.a, block[11], 19);
        self.a = operation_1(self.a, self.b, self.c, self.d, block[12], 3);
        self.d = operation_1(self.d, self.a, self.b, self.c, block[13], 7);
        self.c = operation_1(self.c, self.d, self.a, self.b, block[14], 11);
        self.b = operation_1(self.b, self.c, self.d, self.a, block[15], 19);
    }

    fn round_2(&mut self, block: &[u32]) {
        self.a = operation_2(self.a, self.b, self.c, self.d, block[0], 3);
        self.d = operation_2(self.d, self.a, self.b, self.c, block[4], 5);
        self.c = operation_2(self.c, self.d, self.a, self.b, block[8], 9);
        self.b = operation_2(self.b, self.c, self.d, self.a, block[12], 13);
        self.a = operation_2(self.a, self.b, self.c, self.d, block[1], 3);
        self.d = operation_2(self.d, self.a, self.b, self.c, block[5], 5);
        self.c = operation_2(self.c, self.d, self.a, self.b, block[9], 9);
        self.b = operation_2(self.b, self.c, self.d, self.a, block[13], 13);
        self.a = operation_2(self.a, self.b, self.c, self.d, block[2], 3);
        self.d = operation_2(self.d, self.a, self.b, self.c, block[6], 5);
        self.c = operation_2(self.c, self.d, self.a, self.b, block[10], 9);
        self.b = operation_2(self.b, self.c, self.d, self.a, block[14], 13);
        self.a = operation_2(self.a, self.b, self.c, self.d, block[3], 3);
        self.d = operation_2(self.d, self.a, self.b, self.c, block[7], 5);
        self.c = operation_2(self.c, self.d, self.a, self.b, block[11], 9);
        self.b = operation_2(self.b, self.c, self.d, self.a, block[15], 13);
    }

    fn round_3(&mut self, block: &[u32]) {
        self.a = operation_3(self.a, self.b, self.c, self.d, block[0], 3);
        self.d = operation_3(self.d, self.a, self.b, self.c, block[8], 9);
        self.c = operation_3(self.c, self.d, self.a, self.b, block[4], 11);
        self.b = operation_3(self.b, self.c, self.d, self.a, block[12], 15);
        self.a = operation_3(self.a, self.b, self.c, self.d, block[2], 3);
        self.d = operation_3(self.d, self.a, self.b, self.c, block[10], 9);
        self.c = operation_3(self.c, self.d, self.a, self.b, block[6], 11);
        self.b = operation_3(self.b, self.c, self.d, self.a, block[14], 15);
        self.a = operation_3(self.a, self.b, self.c, self.d, block[1], 3);
        self.d = operation_3(self.d, self.a, self.b, self.c, block[9], 9);
        self.c = operation_3(self.c, self.d, self.a, self.b, block[5], 11);
        self.b = operation_3(self.b, self.c, self.d, self.a, block[13], 15);
        self.a = operation_3(self.a, self.b, self.c, self.d, block[3], 3);
        self.d = operation_3(self.d, self.a, self.b, self.c, block[11], 9);
        self.c = operation_3(self.c, self.d, self.a, self.b, block[7], 11);
        self.b = operation_3(self.b, self.c, self.d, self.a, block[15], 15);
    }
}

impl Digest for MD4 {
    const BLOCKSIZE: usize = 64;
    const OUTPUT_SIZE: usize = 16;
    const OID: ObjectIdentifier = MD4_OID;

    fn new() -> Self {
        Self {
            a: A,
            b: B,
            c: C,
            d: D,
        }
    }

    fn update(&mut self, message: &[u8]) -> &mut Self {
        self.update_with_length(message, message.len())
    }

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
            self.a = self.a.wrapping_add(A);
            self.b = self.b.wrapping_add(B);
            self.c = self.c.wrapping_add(C);
            self.d = self.d.wrapping_add(D);
        }

        self
    }

    fn digest(&mut self) -> Vec<u8> {
        // Generate the output
        let mut out = vec![];
        out.extend(self.a.to_le_bytes().to_vec());
        out.extend(self.b.to_le_bytes().to_vec());
        out.extend(self.c.to_le_bytes().to_vec());
        out.extend(self.d.to_le_bytes().to_vec());

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
