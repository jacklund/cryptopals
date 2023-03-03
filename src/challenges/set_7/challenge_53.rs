#[cfg(test)]
mod tests {
    use super::super::*;
    use anyhow::*;
    use lazy_static::lazy_static;
    use rand;
    use std::collections::HashMap;

    // NOTE: I followed https://www.schneier.com/wp-content/uploads/2016/02/paper-preimages.pdf for
    // the algorithm. This was difficult because that paper had some errors in it that took some
    // time to figure out and correct in my implementation
    //
    // The basic idea is to generate a message that hashes to the same value as a target message.
    // We do this by generating an "expandable" message, basically a set of pairs of messages that
    // hash to the same value, one of which is short (1 block) and the other is long (> 1 block).
    // We find a "bridge" message which, when hashed with the last hash of the expandable message,
    // hashes to a value of one of the intermediate hashes of the target message. We then generate
    // a message prefix from the expandable message of the correct size, add the "bridge" message
    // and the tail few blocks of the original message, and it should hash to the same as the
    // original message.

    lazy_static! {
        // We use zero blocks as our dummy blocks, doesn't seem to matter
        static ref DUMMY_BLOCK: Vec<u8> = vec![0u8; BLOCKSIZE];

        // Size of our hash, makes hash collisions happen faster
        static ref HASH_SIZE: usize = 4;

        // Our IV, also zeroes
        static ref IV: Vec<u8> = vec![0u8; *HASH_SIZE];
    }

    // Our expandable message
    struct ExpandableMessage {
        k: u32,
        c: Vec<[Vec<u8>; 2]>,
    }

    impl ExpandableMessage {
        fn new(k: u32, c: Vec<[Vec<u8>; 2]>) -> Self {
            Self { k, c }
        }

        // Produce a message from our expandable message
        fn produce_message(&self, length: usize) -> Result<Vec<u8>> {
            if (length as u32) > 2u32.pow(self.k) + self.k - 1 || (length as u32) < self.k {
                Err(anyhow!("Bad length"))
            } else {
                // Our output message
                let mut message = vec![];

                // T from the paper - the remaining length to be added
                let t = length as u32 - self.k;

                // Use the bit value in the given position in t to determine whether we use the
                // first (short) message, or the second (long) message
                for i in 0..=self.k - 1 {
                    // Index is 1 if the bit at position i in t is 1, otherwise it's 0
                    let index = (t & (1u32 << i)) >> i;

                    // Use either the first or second message depending on the value of index
                    message.extend(&self.c[i as usize][index as usize]);
                }
                Ok(message)
            }
        }
    }

    // The algorithm. I call this V1 in case I decided to implement their "more efficient" variant
    struct KelseySchneierV1 {
        short_hashes: HashMap<Vec<u8>, Vec<u8>>,
        long_hashes: HashMap<Vec<u8>, Vec<u8>>,
    }

    impl KelseySchneierV1 {
        fn new() -> Self {
            Self {
                short_hashes: HashMap::new(),
                long_hashes: HashMap::new(),
            }
        }

        // Look for a long and short block which hash to the same value
        fn search_hashes(
            &mut self,
            block: &[u8],
            dummy_blocks: &[u8],
            iv: &[u8],
            dummy_hash: &[u8],
        ) -> Option<(Vec<u8>, Vec<u8>, Vec<u8>)> {
            // Get the hashes of a single block and the block appended to the dummy blocks
            // above
            let short_hash = md::<NoPadding>(iv, block);
            let long_hash = md::<NoPadding>(dummy_hash, block);

            // Create our "long" message (just the given block prepended with the dummy blocks"
            // The short message is just the block itself
            let mut long_message = dummy_blocks.to_vec();
            long_message.extend(block);
            assert_eq!(long_hash, md::<NoPadding>(iv, &long_message));

            // Unlikely, but...
            if short_hash == long_hash {
                Some((block.to_vec(), long_message, short_hash))
            } else {
                // Compare the short hash with our list of long hashes
                match self.long_hashes.get(&short_hash) {
                    Some(long_block) => {
                        // Found one, create a long message from the block, and return it and the
                        // short message, along with the hash
                        let mut long_message = dummy_blocks.to_vec();
                        long_message.extend(long_block);
                        assert_eq!(short_hash, md::<NoPadding>(iv, &long_message));
                        Some((block.to_vec(), long_message, short_hash))
                    }

                    // Compare the long hash with our list of short hashes
                    None => match self.short_hashes.get(&long_hash) {
                        Some(short_block) => {
                            // Found one. Return the short block we found with our long message and
                            // the hash
                            assert_eq!(long_hash, md::<NoPadding>(iv, &long_message));
                            assert_eq!(
                                md::<NoPadding>(iv, short_block),
                                md::<NoPadding>(iv, &long_message)
                            );
                            Some((short_block.clone(), long_message, long_hash))
                        }
                        None => {
                            // No luck, add the short and long hashes to the lookup maps, and
                            // return
                            self.short_hashes.insert(short_hash, block.to_vec());
                            self.long_hashes.insert(long_hash, block.to_vec());
                            None
                        }
                    },
                }
            }
        }

        // Find a pair of messages, one a single block long and the other 'a' blocks long, which
        // hash to the same value
        fn find_collision(&mut self, a: usize, iv: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
            // Create a vector of 'a' dummy blocks
            let dummy_blocks = (0..a - 1).fold(vec![], |mut a, _| {
                a.extend(DUMMY_BLOCK.clone());
                a
            });

            // Get the hash of just the dummy blocks
            let dummy_hash = md::<NoPadding>(iv, &dummy_blocks);

            // Generate random blocks
            let ret = std::iter::repeat_with(|| {
                std::iter::repeat_with(rand::random::<u8>)
                    .take(BLOCKSIZE)
                    .collect::<Vec<u8>>()
            })
            .find_map(|bytes| {
                // Find hash collisions between the short block and any long blocks, or the long
                // block and any short blocks
                self.search_hashes(&bytes, &dummy_blocks, iv, &dummy_hash)
            })
            .unwrap();

            // Clear out our maps
            self.long_hashes.clear();
            self.short_hashes.clear();

            ret
        }

        // Make our expandable message
        fn make_expandable_message(&mut self, iv: &[u8], k: u32) -> (ExpandableMessage, Vec<u8>) {
            // c is a list of pairs of message, the first a single block long, the second multiple
            // blocks long
            let mut c = Vec::<[Vec<u8>; 2]>::new();

            // Our beginning hash value
            let mut h_tmp = iv.to_vec();

            // Our two messages
            let mut m0;
            let mut m1;

            // Create our list of message pairs, the first of which is a single block long, the
            // second is 2**i + 1 blocks long
            //
            // NOTE: this is one of the places where the paper is just wrong. In there, they say
            // that i goes from 0 to k-1, and that k - i - 1 is the index into C, which basically
            // reverses the order of C, and makes the algorithm fail. Cost me days debugging this.
            // Really annoying.
            for i in 0..=(k - 1) {
                (m0, m1, h_tmp) = self.find_collision(2usize.pow(i) + 1, &h_tmp);
                c.push([m0, m1]);
            }

            (ExpandableMessage::new(k, c), h_tmp)
        }
    }

    #[test]
    fn challenge_53() {
        // Our k value
        let k = 5;

        // Our target message, which will be 2**k + k + 1 blocks long
        let target_message = std::iter::repeat_with(rand::random::<u8>)
            .take((2usize.pow(k) + k as usize + 1) * BLOCKSIZE)
            .collect::<Vec<u8>>();

        // Break our message up into blocks
        let target_message_blocks = target_message
            .chunks(BLOCKSIZE)
            .map(|c| c.to_vec())
            .collect::<Vec<Vec<u8>>>();

        // Make our expandable message
        let (expandable_message, last_hash) =
            KelseySchneierV1::new().make_expandable_message(&IV, k);

        // Hash the target message and keep the intermediate hashes
        let (hash, intermediate_hashes) = md_with_states::<MDPadding>(&IV, &target_message);

        // Create a HashMap of intermediate hash => index
        let hash_lookup =
            intermediate_hashes
                .iter()
                .enumerate()
                .fold(HashMap::new(), |mut map, (i, hash)| {
                    if i >= (k as usize + 1) && i <= (2u32.pow(k) + k - 1) as usize {
                        map.insert(hash, i);
                    }
                    map
                });

        // Find our message linking our expandable message to the last blocks of the target
        // message. We generate a bunch of random messages, and find one that hashes to one of the
        // intermediate hash values from the target message.
        let (j, link_message, _link_hash) = std::iter::repeat_with(|| {
            std::iter::repeat_with(rand::random::<u8>)
                .take(BLOCKSIZE)
                .collect::<Vec<u8>>()
        })
        .find_map(|bytes| {
            // We use the hash from our expandable message because any message we produce from that
            // will hash to that value, and we'll be appending this message to that.
            let hash = md::<NoPadding>(&last_hash, &bytes);

            hash_lookup.get(&hash).map(|j| (j, bytes, hash))
        })
        .unwrap();

        // Time to build our message
        // Here's another place where the paper is incorrect - it says to produce a message that is
        // j-1 blocks long, but that doesn't work - it's always one block short.

        // Create our message - start with the blocks from the expandable message, append the link
        // message block and then pull the last blocks from the original message (so that we keep
        // the padding and length block from the MD padding)
        let mut message = expandable_message.produce_message(*j).unwrap();
        message.extend(link_message);
        message.extend(
            target_message_blocks[*j + 1..]
                .iter()
                .flatten()
                .cloned()
                .collect::<Vec<u8>>(),
        );

        assert_eq!(target_message.len(), message.len());

        let expandable_hash = md::<MDPadding>(&IV, &message);

        assert_eq!(hash, expandable_hash);
        assert_ne!(target_message, message);
    }
}
