#[cfg(test)]
mod tests {
    use crate::{find_single_byte_key, util::unhexify};
    use std::fs::File;
    use std::io::{BufRead, BufReader};

    #[test]
    fn challenge_4() {
        let (_score, plaintext) = BufReader::new(File::open("files/4.txt").unwrap())
            .lines()
            .fold(
                (0usize, String::new()),
                |(last_score, last_plaintext), line| {
                    let (_key, score, plaintext) =
                        find_single_byte_key(&unhexify(&line.unwrap()).unwrap());
                    if score > last_score {
                        (score, plaintext)
                    } else {
                        (last_score, last_plaintext)
                    }
                },
            );

        assert_eq!("Now that the party is jumping\n", plaintext);
    }
}
