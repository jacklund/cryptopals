use anyhow::{anyhow, Result};

/// Serialize data with PKCS #7 padding
pub trait Serialize {
    fn pkcs7_serialize(&self, blocksize: usize) -> Vec<u8>;
}

/// Deserialize data from PKCS #7 padding
pub trait Deserialize {
    fn pkcs7_deserialize(&self, blocksize: usize) -> Result<Vec<u8>>;
}

fn get_padding_size(datasize: usize, blocksize: usize) -> usize {
    match datasize % blocksize {
        0 => blocksize,
        value => blocksize - value,
    }
}

/// Check whether the data is properly PKCS7 padded
pub fn check_padding(data: &[u8], blocksize: usize) -> Result<usize> {
    if data.len() % blocksize != 0 {
        return Err(anyhow!("Bad padding"));
    }

    let maybe_padding = data[data.len() - 1];
    if (maybe_padding as usize) > blocksize || maybe_padding == 0 {
        // We should always have padding
        Err(anyhow!("Bad padding"))
    } else if data[data.len() - maybe_padding as usize..]
        .iter()
        .all(|b| *b == maybe_padding)
    {
        Ok(maybe_padding as usize)
    } else {
        Err(anyhow!("Bad padding"))
    }
}

impl Serialize for &[u8] {
    fn pkcs7_serialize(&self, blocksize: usize) -> Vec<u8> {
        // Check if it's already serialized
        if self.pkcs7_deserialize(blocksize).is_ok() {
            return self.to_vec();
        }

        let padding_size = get_padding_size(self.len(), blocksize);
        let mut vec = self.to_vec();
        if padding_size > 0 {
            vec.extend(std::iter::repeat(padding_size as u8).take(padding_size));
        }

        vec
    }
}

impl Deserialize for &[u8] {
    fn pkcs7_deserialize(&self, blocksize: usize) -> Result<Vec<u8>> {
        let padding_value = check_padding(self, blocksize)?;

        Ok(self[..self.len() - padding_value].to_vec())
    }
}

impl Serialize for Vec<u8> {
    fn pkcs7_serialize(&self, blocksize: usize) -> Vec<u8> {
        self.as_slice().pkcs7_serialize(blocksize)
    }
}

impl Deserialize for Vec<u8> {
    fn pkcs7_deserialize(&self, blocksize: usize) -> Result<Vec<u8>> {
        self.as_slice().pkcs7_deserialize(blocksize)
    }
}

#[cfg(test)]
mod tests {
    use super::Serialize;
    use super::*;

    #[test]
    fn test_serialize() {
        let test = |blocksize: usize, size: usize| {
            let data: Vec<u8> = std::iter::repeat(b'A').take(size).collect();
            let mut expected: Vec<u8> = std::iter::repeat(b'A').take(size).collect();
            let padding_size = get_padding_size(size, blocksize);
            expected.extend(
                std::iter::repeat(padding_size as u8)
                    .take(padding_size)
                    .collect::<Vec<u8>>(),
            );
            assert_eq!(expected, data.pkcs7_serialize(blocksize));
        };

        test(16, 24);
        test(16, 32);
    }

    #[test]
    fn test_deserialize() {
        let test_good = |blocksize: usize, size: usize| {
            let expected: Vec<u8> = std::iter::repeat(b'A').take(size).collect();
            let mut data: Vec<u8> = std::iter::repeat(b'A').take(size).collect();
            let padding_size = get_padding_size(size, blocksize);
            data.extend(
                std::iter::repeat(padding_size as u8)
                    .take(padding_size)
                    .collect::<Vec<u8>>(),
            );
            let result = data.pkcs7_deserialize(blocksize);
            assert!(result.is_ok());
            assert_eq!(expected, result.unwrap());
        };

        test_good(16, 24);
        test_good(16, 32);

        let mut bad: Vec<u8> = std::iter::repeat(b'A').take(12).collect();
        bad.extend(vec![0x1, 0x2, 0x3, 0x4]);
        let result = bad.pkcs7_deserialize(16);
        assert!(result.is_err());

        let bad: Vec<u8> = std::iter::repeat(b'A').take(16).collect();
        let result = bad.pkcs7_deserialize(16);
        assert!(result.is_err());
    }
}
