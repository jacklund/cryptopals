#[cfg(test)]
mod tests {
    use crate::digest::sha1::*;
    use crate::dsa::*;
    use crate::util::{hexify, unhexify};
    use itertools::Itertools;
    use lazy_static::lazy_static;
    use num::Num;
    use num_bigint::*;
    use num_modular::ModularUnaryOps;
    use std::fs::File;
    use std::io::{BufRead, BufReader};

    lazy_static! {
        static ref p: BigUint = BigUint::from_bytes_be(
            &unhexify(
                "800000000000000089e1855218a0e7dac38136ffafa72eda7\
                 859f2171e25e65eac698c1702578b07dc2a1076da241c76c6\
                 2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe\
                 ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2\
                 b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87\
                 1a584471bb1"
            )
            .unwrap()
        );
        static ref q: BigUint =
            BigUint::from_bytes_be(&unhexify("f4f47f05794b256174bba6e9b396a7707e563c5b").unwrap());
        static ref g: BigUint = BigUint::from_bytes_be(
            &unhexify(
                "5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119\
                 458fef538b8fa4046c8db53039db620c094c9fa077ef389b5\
                 322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047\
                 0f5b64c36b625a097f1651fe775323556fe00b3608c887892\
                 878480e99041be601a62166ca6894bdd41a7054ec89f756ba\
                 9fc95302291"
            )
            .unwrap()
        );
    }

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
            let diff_invm = ((first.s.clone() - second.s.clone()) % q.clone()).invm(&q);
            if let Some(diff_invm) = diff_invm {
                let k = ((first.hash.clone() - second.hash.clone()) % q.clone()) * diff_invm
                    % q.clone();
                let (private, _public) = get_keys_from_k(first, &k, &p, &q, &g).unwrap();
                let sha = hexify(&sha1(hexify(&private.value().to_bytes_be()).as_bytes()));
                assert_eq!("ca8f6f7c66fa362d40760d135b763eb8527d3d52", sha);
                return;
            }
        }
    }
}
