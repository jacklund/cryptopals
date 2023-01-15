#[cfg(test)]
mod tests {
    use crate::cracking::untemper;
    use crate::mt19937::MarsenneTwister;
    use rand::RngCore;

    // Twenty-Second cryptopals challenge - https://cryptopals.com/sets/3/challenges/22
    // This one is silly - someone seeds the MT with the timestamp, and all you need to do
    // is grab the first random value, and then use a range of times up to now for the seed
    // guesses.
    #[test]
    fn challenge23() {
        let mut mt = MarsenneTwister::from_seed(rand::random::<u32>());
        let mut values = vec![];
        for _ in 0..624 {
            values.push(mt.next_u32());
        }

        let mut generator = vec![];
        for index in 0..624 {
            generator.push(untemper(values[index]));
        }

        let mut mt2 = MarsenneTwister::from_splice(&generator);
        for index in 0..624 {
            println!("Index = {}", index);
            assert_eq!(values[index], mt2.next_u32());
        }
    }
}
