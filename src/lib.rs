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
            ('A', 10),
            ('B', 11),
            ('C', 12),
            ('D', 13),
            ('E', 14),
            ('F', 15),
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
            (10, 'A'),
            (11, 'B'),
            (12, 'C'),
            (13, 'D'),
            (14, 'E'),
            (15, 'F'),
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
}

pub fn hexify(mut value: u64) -> String {
    let mut chars = vec![];
    while value > 0 {
        chars.push(*NUMBERS_TO_HEX.get(&((value & 0x0F) as u8)).unwrap());
        value >>= 4;
    }

    chars.iter().rev().collect()
}

pub fn unhexify(hex: &str) -> Result<Vec<u8>> {
    hex.to_uppercase()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex() {
        let value: Vec<u8> = vec![163];
        assert_eq!(unhexify("A3").unwrap(), value);
        assert!(unhexify("X3").is_err());
        assert!(matches!(hexify(163).as_str(), "A3"));
    }

    #[test]
    fn test_base64() {
        assert_eq!(
            to_base64("Many hands make light work.".as_bytes()),
            "TWFueSBoYW5kcyBtYWtlIGxpZ2h0IHdvcmsu"
        );
    }
}
