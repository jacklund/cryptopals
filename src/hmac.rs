use crate::digest::sha1::SHA1;
use crate::digest::Digest;

pub fn hmac_sha1(key: &[u8], message: &[u8]) -> Vec<u8> {
    hmac::<SHA1>(key, message)
}

pub fn hmac<H>(key: &[u8], message: &[u8]) -> Vec<u8>
where
    H: Digest,
{
    // Get key the size of our block, derived from our key
    let mut blocksize_key: Vec<u8> = key.to_vec();
    println!("key = {:x?}", key);

    // If it's bigger than a block, repeatedly hash until it's smaller
    if blocksize_key.len() > H::BLOCKSIZE {
        loop {
            blocksize_key = H::new().update(&blocksize_key).digest();
            println!("blocksize_key = {:x?}", blocksize_key);
            if blocksize_key.len() <= H::BLOCKSIZE {
                break;
            }
        }
    };

    // Pad it to the right with zeroes
    if blocksize_key.len() < H::BLOCKSIZE {
        blocksize_key.extend(
            std::iter::repeat(0u8)
                .take(H::BLOCKSIZE - blocksize_key.len())
                .collect::<Vec<u8>>(),
        );
        println!("blocksize_key = {:x?}", blocksize_key);
    }

    // H(K ^ ipad) || m
    let mut inner = blocksize_key
        .iter()
        .map(|a| a ^ 0x36u8)
        .collect::<Vec<u8>>();
    inner.extend_from_slice(message);
    let hashed_inner = H::new().update(&inner).digest();

    // (K ^ opad) || H((K ^ ipad) || m)
    let mut outer = blocksize_key
        .iter()
        .map(|a| a ^ 0x5cu8)
        .collect::<Vec<u8>>();
    outer.extend(hashed_inner);

    // Hash the whole thing
    H::new().update(&outer).digest()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::unhexify;

    #[test]
    fn test_hmac_sha1() {
        let string = "Terminator X: Bring the noise";
        let key = "SuperSecretKey";

        assert_eq!(
            unhexify("b40438338a19a7d879221946330058bbda92d7f8").unwrap(),
            hmac_sha1(key.as_bytes(), string.as_bytes())
        );
    }
}
