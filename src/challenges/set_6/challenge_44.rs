#[cfg(test)]
mod tests {
    use crate::digest::sha1::*;
    use crate::dsa::*;
    use crate::util::hexify;
    use itertools::Itertools;
    use num::Num;
    use num_bigint::*;
    use std::fs::File;
    use std::io::{BufRead, BufReader};

    fn parse_signature(message: &str, s: &str, r: &str, m: &str) -> Signature {
        Signature::new(
            &BigUint::from_str_radix(r.split_once(' ').unwrap().1, 10).unwrap(),
            &BigUint::from_str_radix(s.split_once(' ').unwrap().1, 10).unwrap(),
            message.split_once(' ').unwrap().1,
            &BigUint::from_str_radix(m.split_once(' ').unwrap().1, 16).unwrap(),
        )
    }

    #[test]
    fn challenge_44() {
        // Use the default values for p, q and g
        let dsa = DSA::default();

        // Read the file, parsing every 4 lines into a signature
        let mut signatures = BufReader::new(File::open("files/44.txt").unwrap())
            .lines()
            .chunks(4)
            .into_iter()
            .map(|mut chunk| {
                parse_signature(
                    &chunk.next().unwrap().unwrap(),
                    &chunk.next().unwrap().unwrap(),
                    &chunk.next().unwrap().unwrap(),
                    &chunk.next().unwrap().unwrap(),
                )
            })
            .collect::<Vec<Signature>>();

        // Sort the signatures by r
        signatures.sort_by(|s1, s2| s1.r.partial_cmp(&s2.r).unwrap());

        // Group the signatures by r, additionally sorting each group by s descending so
        // that we can perform the subtraction below without underflow
        let groups = signatures
            .iter()
            .group_by(|s| s.r.clone())
            .into_iter()
            .map(|(_, grp)| grp.into_iter().cloned().collect::<Vec<Signature>>())
            .map(|mut v| {
                v.sort_by(|s1, s2| s2.s.partial_cmp(&s1.s).unwrap());
                v
            })
            .collect::<Vec<Vec<Signature>>>();
        let mut groups_iter = groups.iter();

        // Loop through the groups and calculate k, and from there, the keys
        loop {
            let group = groups_iter.next().unwrap();

            // Grab the first two
            let first = &group[0];
            let second = &group[1];

            // Make sure the inverse mod exists
            if let Some((private, _public)) = dsa.get_keys_from_repeated_nonce(&first, &second) {
                let sha = hexify(&sha1(hexify(&private.value().to_bytes_be()).as_bytes()));
                assert_eq!("ca8f6f7c66fa362d40760d135b763eb8527d3d52", sha);
                return;
            }
        }
    }
}
