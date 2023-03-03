use super::Digest;
use asn1::{oid, ObjectIdentifier};

const SHA1_OID: ObjectIdentifier = oid!(1, 3, 14, 3, 2, 26);

pub struct SHA1 {
    h0: u32,
    h1: u32,
    h2: u32,
    h3: u32,
    h4: u32,
}

impl SHA1 {
    pub fn new_with_init(h0: u32, h1: u32, h2: u32, h3: u32, h4: u32) -> Self {
        Self { h0, h1, h2, h3, h4 }
    }
}

pub fn get_padding(length: usize) -> Vec<u8> {
    let bitlength: u64 = (length * 8) as u64;
    let mut padding_size_bytes: usize = 64 - (length % 64);
    if padding_size_bytes < 9 {
        padding_size_bytes += 64;
    }
    let mut ret = vec![];
    ret.push(0x80u8); // Append '1' bit
    let padding_prefix_size = padding_size_bytes - 8;
    ret.extend(
        std::iter::repeat(0u8)
            .take(padding_prefix_size - 1)
            .collect::<Vec<u8>>(),
    );
    ret.extend(bitlength.to_be_bytes());

    ret
}

fn add32(a: u32, b: u32) -> u32 {
    ((a as u64 + b as u64) & 0xFFFFFFFF) as u32
}

impl Digest for SHA1 {
    const BLOCKSIZE: usize = 64;
    const OUTPUT_SIZE: usize = 20;
    const OID: ObjectIdentifier = SHA1_OID;

    fn new() -> Self {
        SHA1::new_with_init(0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0)
    }

    fn update(&mut self, message: &[u8]) -> &mut Self {
        self.update_with_length(message, message.len())
    }

    fn update_with_length(&mut self, message: &[u8], length: usize) -> &mut Self {
        // Break message into 512-bit chunks
        let mut buffer = message.to_vec();
        buffer.extend(get_padding(length));
        for chunk512 in buffer.chunks(Self::BLOCKSIZE) {
            // Break each chunk into 32-bit "words"
            let mut words: Vec<u32> = vec![];
            for chunk32 in chunk512.chunks(4) {
                words.push(u32::from_be_bytes(chunk32.try_into().unwrap()));
            }

            // Extend the 16 32-bit words into 80 32-bit words
            for index in 16..80 {
                words.push(
                    (words[index - 3] ^ words[index - 8] ^ words[index - 14] ^ words[index - 16])
                        .rotate_left(1),
                );
            }

            let mut a = self.h0;
            let mut b = self.h1;
            let mut c = self.h2;
            let mut d = self.h3;
            let mut e = self.h4;

            // Main loop
            let mut f: u32;
            let mut k: u32;
            for (index, word) in words.iter().enumerate().take(80) {
                if index < 20 {
                    f = (b & c) | ((!b) & d);
                    k = 0x5A827999;
                } else if index < 40 {
                    f = b ^ c ^ d;
                    k = 0x6ED9EBA1;
                } else if index < 60 {
                    f = (b & c) | (b & d) | (c & d);
                    k = 0x8F1BBCDC;
                } else {
                    f = b ^ c ^ d;
                    k = 0xCA62C1D6;
                }

                let temp: u32 = add32(add32(add32(add32(a.rotate_left(5), f), e), k), *word);
                e = d;
                d = c;
                c = b.rotate_left(30);
                b = a;
                a = temp;
            }

            self.h0 = add32(self.h0, a);
            self.h1 = add32(self.h1, b);
            self.h2 = add32(self.h2, c);
            self.h3 = add32(self.h3, d);
            self.h4 = add32(self.h4, e);
        }

        self
    }

    fn digest(&mut self) -> Vec<u8> {
        let mut hh = vec![];
        hh.extend(self.h0.to_be_bytes());
        hh.extend(self.h1.to_be_bytes());
        hh.extend(self.h2.to_be_bytes());
        hh.extend(self.h3.to_be_bytes());
        hh.extend(self.h4.to_be_bytes());

        hh
    }
}

pub fn sha1(message: &[u8]) -> Vec<u8> {
    SHA1::new().update(message).digest()
}

pub fn sha1_mac(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut value = key.to_vec();
    value.extend(message);
    SHA1::new().update(&value).digest()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha1_padding() {
        let message: Vec<u8> = vec![0x61, 0x62, 0x63, 0x64, 0x65];
        let mut padded = message.clone();
        padded.extend(get_padding(message.len()));

        let expected_value = vec![
            0x61, 0x62, 0x63, 0x64, 0x65, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x28,
        ];

        assert_eq!(expected_value, padded);
    }

    #[test]
    fn test_sha1() {
        let mut sha = SHA1::new().update("Hello, World!".as_bytes()).digest();

        let mut expected_value = vec![
            0x0a, 0x0a, 0x9f, 0x2a, 0x67, 0x72, 0x94, 0x25, 0x57, 0xab, 0x53, 0x55, 0xd7, 0x6a,
            0xf4, 0x42, 0xf8, 0xf6, 0x5e, 0x01,
        ];

        assert_eq!(expected_value, sha);

        sha = SHA1::new().update("".as_bytes()).digest();

        expected_value = vec![
            0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95, 0x60,
            0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09,
        ];

        assert_eq!(expected_value, sha);
    }
}
