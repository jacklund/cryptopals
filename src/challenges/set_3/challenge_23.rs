#[cfg(test)]
mod tests {
    use crate::cracking::untemper;
    use crate::mt19937::MarsenneTwister;
    use rand::RngCore;

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
