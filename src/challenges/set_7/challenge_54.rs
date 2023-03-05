#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::herding::*;
    use lazy_static::lazy_static;

    lazy_static! {
        // We use zero blocks as our dummy blocks, doesn't seem to matter
        static ref DUMMY_BLOCK: Vec<u8> = vec![0u8; BLOCKSIZE];

        // Size of our hash, makes hash collisions happen faster
        static ref HASH_SIZE: usize = 4;

        // Our IV, also zeroes
        static ref IV: Vec<u8> = vec![0u8; *HASH_SIZE];
    }

    #[test]
    fn challenge_54() {
        // Our k value
        let k = 5;

        let (diamond, hash) = DiamondStructure::generate(k, *HASH_SIZE, &*IV);
        let prefix = b"YELLOW SUBMARINE";
        let message = diamond.create_message(prefix, &*IV);

        assert_eq!(hash, md::<MDPadding>(&IV, &message));
    }
}
