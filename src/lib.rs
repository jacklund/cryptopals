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

    static ref CHAR_LIST_BY_FREQUENCY: Vec<char> = {
        " etaoinshrdlu"
            .chars().flat_map(|c| {
                if c == ' ' {
                    vec![c]
                } else {
                    vec![
                        c,
                        c.to_uppercase().collect::<Vec<char>>()[0]
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

pub fn create_histogram(string: &str) -> Vec<(char, usize)> {
    let mut list = string
        .chars()
        .fold(HashMap::<char, usize>::new(), |mut hashmap, c| {
            match hashmap.get(&c) {
                Some(count) => {
                    let new = count + 1;
                    hashmap.insert(c, new);
                }
                None => {
                    hashmap.insert(c, 1);
                }
            };
            hashmap
        })
        .into_iter()
        .collect::<Vec<(char, usize)>>();
    list.sort_by(|(_, count1), (_, count2)| count2.cmp(count1));

    list
}

pub fn try_xor_key(key: &[u8], ciphertext: &[u8]) -> (usize, String) {
    let xored = xor(key, ciphertext).unwrap();
    let plaintext = std::str::from_utf8(&xored).unwrap().to_string();
    let score = get_score(&plaintext);
    (score, plaintext)
}

pub fn keystream_from_byte(key: u8, size: usize) -> Vec<u8> {
    let mut key_stream = vec![];
    key_stream.extend(std::iter::repeat(key).take(size));
    key_stream
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
}
