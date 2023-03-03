#[cfg(test)]
mod tests {
    use super::super::*;
    use itertools::*;
    use rand;
    use std::collections::HashMap;

    fn find_collisions(iv: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>, u32) {
        // Keep track of the hashes
        let mut hashes = HashMap::<Vec<u8>, Vec<u8>>::new();

        // Keep count of how many times we call hash function
        let mut count = 0u32;

        // Generate random messages
        for bytes in std::iter::repeat_with(|| {
            std::iter::repeat_with(rand::random::<u8>)
                .take(BLOCKSIZE)
                .collect::<Vec<u8>>()
        }) {
            let hash = md::<MDPadding>(iv, &bytes);
            count += 1;

            // Find those collisions
            if let std::collections::hash_map::Entry::Vacant(e) = hashes.entry(hash.clone()) {
                e.insert(bytes.to_vec());
            } else {
                return (
                    bytes.to_vec(),
                    hashes.get(&hash).unwrap().clone(),
                    hash,
                    count,
                );
            }
        }

        unreachable!()
    }

    fn find_multicollisions(iv: &[u8], iterations: usize) -> (Vec<Vec<u8>>, u32) {
        let mut collisions = vec![];

        let mut hash = iv.to_vec();
        let mut block_a;
        let mut block_b;
        let mut count: u32;
        let mut total_count: u32 = 0;
        for _ in 0..iterations {
            (block_a, block_b, hash, count) = find_collisions(&hash);
            collisions.push(vec![block_a, block_b]);
            total_count += count;
        }

        (
            collisions
                .iter()
                .multi_cartesian_product()
                .map(|blocks| {
                    blocks.iter().fold(Vec::new(), |mut a, block| {
                        a.extend(&(*block).clone());
                        a
                    })
                })
                .collect(),
            total_count,
        )
    }

    #[test]
    fn challenge_52() {
        // Part one: Generate a 2 ^ 5 collisions on a 5-byte hash function
        let hash_size = 5;
        let iv = vec![0u8; hash_size];
        let (collisions, count) = find_multicollisions(&iv, 5);
        println!(
            "num collisions = {}, number of times hash function called = {}",
            collisions.len(),
            count
        );

        let n = hash_size as u32 * 8;
        assert!(count <= n * 2u32.pow(n / 2));

        // Part two: Generate a composite hash function, and show that you can get collisions from
        // the weaker one and use them as collisions of the whole thing
        let f_size = 3;
        let g_size = 4;
        let f_iv = vec![0u8; f_size];
        let g_iv = vec![0u8; g_size];
        let (f_collisions, f_count) = find_multicollisions(&f_iv, g_size);
        let collisions = f_collisions
            .iter()
            .cartesian_product(f_collisions.iter())
            .filter(|(message1, message2)| {
                md::<MDPadding>(&g_iv, message1) == md::<MDPadding>(&g_iv, message2)
            })
            .map(|(m1, m2)| (m1.clone(), m2.clone()))
            .collect::<Vec<(Vec<u8>, Vec<u8>)>>();
        println!("Collisions = {}", collisions.len());
        println!(
            "Hash function called {} times",
            f_count + f_collisions.len().pow(2) as u32
        );
    }
}
