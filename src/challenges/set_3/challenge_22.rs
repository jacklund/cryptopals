#[cfg(test)]
mod tests {
    use crate::mt19937::MarsenneTwister;
    use rand::{Rng, RngCore};
    use std::time;

    fn get_current_timestamp() -> u32 {
        let unix_time = time::SystemTime::now()
            .duration_since(time::UNIX_EPOCH)
            .unwrap();
        (unix_time.as_secs() * 1000) as u32 + unix_time.subsec_millis()
    }

    // Twenty-Second cryptopals challenge - https://cryptopals.com/sets/3/challenges/22
    // This one is silly - someone seeds the MT with the timestamp, and all you need to do
    // is grab the first random value, and then use a range of times up to now for the seed
    // guesses.
    #[test]
    fn challenge22() {
        // Random number of seconds ago
        let wait_time = rand::thread_rng().gen_range(40..1000);
        let seed = get_current_timestamp() - wait_time;
        let mut mt = MarsenneTwister::from_seed(seed);
        let random_value = mt.next_u32();
        // We're supposed to sleep here, but...why?
        // let wait_time = rand::thread_rng().gen_range(40..100);
        // std::thread::sleep(std::time::Duration::from_secs(wait_time));
        let now = get_current_timestamp();
        let found = (now - 100000..now).rev().find(|ts| {
            mt = MarsenneTwister::from_seed(*ts);
            let value = mt.next_u32();
            value == random_value
        });

        assert_eq!(Some(seed), found);
    }
}
