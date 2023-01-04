use anyhow::{anyhow, Result};
use lazy_static::lazy_static;
use std::collections::HashMap;

mod challenges;

lazy_static! {
    static ref HEX_TO_NUMBERS: HashMap<char, u8> = {
        HashMap::from([
            ('0', 0),
            ('1', 1),
            ('2', 2),
            ('3', 3),
            ('4', 4),
            ('5', 5),
            ('6', 6),
            ('7', 7),
            ('8', 8),
            ('9', 9),
            ('a', 10),
            ('b', 11),
            ('c', 12),
            ('d', 13),
            ('e', 14),
            ('f', 15),
        ])
    };
    static ref NUMBERS_TO_HEX: HashMap<u8, char> = {
        HashMap::from([
            (0, '0'),
            (1, '1'),
            (2, '2'),
            (3, '3'),
            (4, '4'),
            (5, '5'),
            (6, '6'),
            (7, '7'),
            (8, '8'),
            (9, '9'),
            (10, 'a'),
            (11, 'b'),
            (12, 'c'),
            (13, 'd'),
            (14, 'e'),
            (15, 'f'),
        ])
    };
    static ref NUMBERS_TO_BASE64: HashMap<u8, char> = {
        HashMap::from([
            (0, 'A'),
            (1, 'B'),
            (2, 'C'),
            (3, 'D'),
            (4, 'E'),
            (5, 'F'),
            (6, 'G'),
            (7, 'H'),
            (8, 'I'),
            (9, 'J'),
            (10, 'K'),
            (11, 'L'),
            (12, 'M'),
            (13, 'N'),
            (14, 'O'),
            (15, 'P'),
            (16, 'Q'),
            (17, 'R'),
            (18, 'S'),
            (19, 'T'),
            (20, 'U'),
            (21, 'V'),
            (22, 'W'),
            (23, 'X'),
            (24, 'Y'),
            (25, 'Z'),
            (26, 'a'),
            (27, 'b'),
            (28, 'c'),
            (29, 'd'),
            (30, 'e'),
            (31, 'f'),
            (32, 'g'),
            (33, 'h'),
            (34, 'i'),
            (35, 'j'),
            (36, 'k'),
            (37, 'l'),
            (38, 'm'),
            (39, 'n'),
            (40, 'o'),
            (41, 'p'),
            (42, 'q'),
            (43, 'r'),
            (44, 's'),
            (45, 't'),
            (46, 'u'),
            (47, 'v'),
            (48, 'w'),
            (49, 'x'),
            (50, 'y'),
            (51, 'z'),
            (52, '0'),
            (53, '1'),
            (54, '2'),
            (55, '3'),
            (56, '4'),
            (57, '5'),
            (58, '6'),
            (59, '7'),
            (60, '8'),
            (61, '9'),
            (62, '+'),
            (63, '/'),
        ])
    };

    static ref CHAR_LIST_BY_FREQUENCY: Vec<u8> = {
        " etaoinshrdlu"
            .bytes().flat_map(|b| {
                if b as char == ' ' {
                    vec![b]
                } else {
                    vec![
                        b,
                        (b as char).to_uppercase().collect::<Vec<char>>()[0] as u8
                    ]
                }
            }).collect()
    };

    // Create a hashmap of char => score based on char frequency
    static ref CHAR_SCORES: HashMap<char, usize> = {
        HashMap::from(
            <Vec<(char, usize)> as TryInto<[(char, usize); 25]>>::try_into(
                " etaoinshrdlu"
                    .chars()
                    .flat_map(|c| {
                        let mut score: usize = 14;
                        score -= 1;
                        if c == ' ' {
                            vec![(c, score)]
                        } else {
                            vec![
                                (c, score),
                                (c.to_uppercase().collect::<Vec<char>>()[0], score),
                            ]
                        }
                    })
                    .collect::<Vec<(char, usize)>>(),
            )
            .unwrap(),
        )
    };
}

pub fn hexify(value: &[u8]) -> String {
    value
        .iter()
        .flat_map(|c| {
            vec![
                *NUMBERS_TO_HEX.get(&(c >> 4)).unwrap(),
                *NUMBERS_TO_HEX.get(&(c & 0x0F)).unwrap(),
            ]
        })
        .collect()
}

pub fn unhexify(hex: &str) -> Result<Vec<u8>> {
    hex.to_lowercase()
        .chars()
        .collect::<Vec<char>>()
        .chunks(2)
        .map(|chunk| match HEX_TO_NUMBERS.get(&chunk[0]) {
            Some(a) => match HEX_TO_NUMBERS.get(&chunk[1]) {
                Some(b) => Ok((a << 4) + b),
                None => Err(anyhow!("Bad hex value: {}", chunk[1])),
            },
            None => Err(anyhow!("Bad hex value: {}", chunk[0])),
        })
        .collect()
}

pub fn to_base64(value: &[u8]) -> String {
    value
        .chunks(3)
        .flat_map(|chunk| {
            let mut values = vec![];
            match chunk.len() {
                3 => {
                    values.push(*NUMBERS_TO_BASE64.get(&(chunk[0] >> 2)).unwrap());
                    values.push(
                        *NUMBERS_TO_BASE64
                            .get(&(((chunk[0] & 0x03) << 4) + (chunk[1] >> 4)))
                            .unwrap(),
                    );
                    values.push(
                        *NUMBERS_TO_BASE64
                            .get(&(((chunk[1] & 0x0F) << 2) + (chunk[2] >> 6)))
                            .unwrap(),
                    );
                    values.push(*NUMBERS_TO_BASE64.get(&(chunk[2] & 0x3F)).unwrap());
                }
                2 => {
                    values.push(*NUMBERS_TO_BASE64.get(&(chunk[0] >> 2)).unwrap());
                    values.push(
                        *NUMBERS_TO_BASE64
                            .get(&(((chunk[0] & 0x03) << 4) + (chunk[1] >> 4)))
                            .unwrap(),
                    );
                    values.push(*NUMBERS_TO_BASE64.get(&((chunk[1] & 0x0F) << 2)).unwrap());
                    values.push('=');
                }
                1 => {
                    values.push(*NUMBERS_TO_BASE64.get(&(chunk[0] >> 2)).unwrap());
                    values.push(*NUMBERS_TO_BASE64.get(&((chunk[0] & 0x03) << 4)).unwrap());
                    values.push('=');
                    values.push('=');
                }
                _ => unreachable!(),
            };
            values
        })
        .collect()
}

pub fn xor(a: &[u8], b: &[u8]) -> Result<Vec<u8>> {
    if a.len() != b.len() {
        Err(anyhow!("Data should be of the same length"))
    } else {
        Ok(a.iter().zip(b).map(|(a, b)| a ^ b).collect())
    }
}

pub fn get_score(string: &str) -> usize {
    string
        .chars()
        .fold(0usize, |acc, c| acc + get_char_score(c))
}

pub fn get_char_score(c: char) -> usize {
    match CHAR_SCORES.get(&c) {
        Some(score) => *score,
        None => 0,
    }
}

pub fn create_histogram(string: &[u8]) -> Vec<(u8, usize)> {
    let mut list = string
        .iter()
        .fold(HashMap::<u8, usize>::new(), |mut hashmap, b| {
            match hashmap.get(b) {
                Some(count) => {
                    let new = count + 1;
                    hashmap.insert(*b, new);
                }
                None => {
                    hashmap.insert(*b, 1);
                }
            };
            hashmap
        })
        .into_iter()
        .collect::<Vec<(u8, usize)>>();
    list.sort_by(|(_, count1), (_, count2)| count2.cmp(count1));

    list
}

pub fn try_xor_key(key: &[u8], ciphertext: &[u8]) -> (usize, String) {
    let xored = xor(key, ciphertext).unwrap();
    match std::str::from_utf8(&xored) {
        Ok(string) => (get_score(string), string.to_string()),
        Err(_) => (0, String::new()),
    }
}

pub fn find_single_byte_key(ciphertext: &[u8]) -> (u8, usize, String) {
    let histogram = create_histogram(ciphertext);
    let ciphertext_val = histogram[0].0;

    // Since p ^ k = c, where p is the plaintext char, k is the key char, and c is the
    // ciphertext char, we can use k = c ^ p. Here, we take the most frequent char in the
    // ciphertext, and xor it with each of the most frequent chars in the English language,
    // and try that as a key. The key that gives us the highest score wins.
    CHAR_LIST_BY_FREQUENCY.iter().fold(
        (0u8, 0usize, String::new()),
        |(last_key, last_score, last_plaintext), b| {
            let key = *b ^ ciphertext_val;
            let (score, plaintext) = try_xor_key(
                &keystream_from_byte(*b ^ ciphertext_val, ciphertext.len()),
                ciphertext,
            );
            if score > last_score {
                (key, score, plaintext)
            } else {
                (last_key, last_score, last_plaintext)
            }
        },
    )
}

pub fn keystream_from_byte(key: u8, size: usize) -> Vec<u8> {
    [key].iter().cycle().take(size).copied().collect()
}

pub fn repeating_key_xor(key: &[u8], plaintext: &[u8]) -> Vec<u8> {
    key.iter()
        .cycle()
        .take(plaintext.len())
        .zip(plaintext)
        .map(|(k, p)| k ^ p)
        .collect()
}

pub fn hamming_distance(a: &[u8], b: &[u8]) -> usize {
    a.iter()
        .zip(b)
        .fold(0u32, |sum, (a, b)| sum + (a ^ b).count_ones()) as usize
}

pub fn break_repeating_key_xor(ciphertext: &[u8]) -> (Vec<u8>, Vec<u8>) {
    // Iterate through various keysizes, chunking the ciphertext into keysize chunks,
    // and find the least average distance between the even and odd chunks
    // That will determine our key size
    let (_distance, keysize) = (2..40).fold(
        (1000f32, 1usize),
        |(last_distance, last_keysize), keysize| {
            // Chunk the ciphertext
            let (odd, even): (Vec<(usize, &[u8])>, Vec<(usize, &[u8])>) = ciphertext
                .chunks(keysize)
                .enumerate()
                .partition(|(i, _chunk)| i % 2 == 0);

            // Compute the average distance
            // This is average distance divided by key length.
            // Since average distance = total distance / number of samples,
            // and number of samples = string length / key length,
            // we end up with average distance = total distance / string length
            let average_distance = odd
                .iter()
                .zip(even)
                .map(|((_, odd_chunk), (_, even_chunk))| hamming_distance(odd_chunk, even_chunk))
                .sum::<usize>() as f32
                / ciphertext.len() as f32;
            if average_distance < last_distance {
                (average_distance, keysize)
            } else {
                (last_distance, last_keysize)
            }
        },
    );

    // Now that we have the key size, chunk the ciphertext in keysize chunks, and then transpose it
    // by taking the first byte of each chunk, then the second, etc. This leaves us with a bunch of
    // single-byte-encrypted ciphertexts.
    let mut nested_vecs: Vec<Vec<u8>> = Vec::new();
    (0..keysize).for_each(|_| nested_vecs.push(Vec::new()));
    let nested_vecs = ciphertext
        .chunks(keysize)
        .fold(nested_vecs, |mut nested_vecs, chunk| {
            chunk
                .iter()
                .enumerate()
                .for_each(|(i, b)| nested_vecs[i].push(*b));

            nested_vecs
        });

    // We find the single-byte key for each transposed ciphertext, and combine each of those into
    // our overall key
    let key = nested_vecs
        .iter()
        .map(|ciphertext| {
            let (key, _score, _plaintext) = find_single_byte_key(ciphertext);
            key
        })
        .collect::<Vec<u8>>();

    // ...and we decrypt
    let plaintext = repeating_key_xor(&key, ciphertext);

    (key, plaintext)
}

pub fn detect_aes_ecb(ciphertext: &[u8], blocksize: usize) -> bool {
    let mut chunks = ciphertext.chunks(blocksize).collect::<Vec<&[u8]>>();
    while let Some(chunk) = chunks.pop() {
        if chunks.iter().any(|other| *other == chunk) {
            return true;
        }
    }

    false
}

pub fn pkcs7_pad(plaintext: &[u8], blocksize: usize) -> Vec<u8> {
    let padding_size = blocksize - (plaintext.len() % blocksize);
    let mut vec = plaintext.to_vec();
    vec.extend(std::iter::repeat(padding_size as u8).take(padding_size));

    vec
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex() {
        let value: Vec<u8> = vec![163];
        assert_eq!(unhexify("a3").unwrap(), value);
        assert!(unhexify("x3").is_err());
        assert!(matches!(hexify(&[0xa3u8]).as_str(), "a3"));
    }

    #[test]
    fn test_base64() {
        assert_eq!(
            to_base64("Many hands make light work.".as_bytes()),
            "TWFueSBoYW5kcyBtYWtlIGxpZ2h0IHdvcmsu"
        );
    }

    #[test]
    fn test_hamming() {
        assert_eq!(
            37,
            hamming_distance("this is a test".as_bytes(), "wokka wokka!!!".as_bytes()),
        );
    }
}
