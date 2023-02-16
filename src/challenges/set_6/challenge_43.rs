#[cfg(test)]
mod tests {
    use crate::digest::sha1::*;
    use crate::dsa::*;
    use crate::util::{hexify, unhexify};
    use num::Num;
    use num_bigint::*;

    #[test]
    fn test_dsa_signature() {
        let message = "This is a test";
        let dsa = DSA::default();
        let (privkey, pubkey) = dsa.generate_keypair();
        let signature = dsa.sign::<SHA1>(&privkey, message);
        assert!(dsa.verify::<SHA1>(&pubkey, message, &signature));
    }

    #[test]
    fn challenge_43() {
        // The givens from the problem
        let public_key = PublicKey::new(BigUint::from_bytes_be(
            &unhexify(
                "84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4\
                 abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004\
                 e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed\
                 1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07b\
                 bb283e6633451e535c45513b2d33c99ea17",
            )
            .unwrap(),
        ));
        let message = "For those that envy a MC it can be hazardous to your health\n\
                        So be friendly, a matter of life and death, just like a etch-a-sketch\n";
        let r = BigUint::from_str_radix("548099063082341131477253921760299949438196259240", 10)
            .unwrap();
        let s = BigUint::from_str_radix("857042759984254168557880549501802188789837994940", 10)
            .unwrap();

        // Calculate the hash
        let hash = sha1(message.as_bytes());
        assert_eq!(
            unhexify("d2d0714f014a9784047eaeccf956520045c45265").unwrap(),
            hash,
        );
        let hash_int = BigUint::from_bytes_be(&hash);

        let signature = Signature::new(&r, &s, message, &hash_int);

        // Find the keys
        let max: u32 = 2u32.pow(16);
        let dsa = DSA::default();
        let (private, _) = (1..max)
            .find_map(
                |k| match dsa.get_keys_from_nonce(&signature, &BigUint::from(k)) {
                    Some((private, public)) => match public.value() == public_key.value() {
                        true => Some((private, public)),
                        false => None,
                    },
                    None => None,
                },
            )
            .unwrap();
        assert_eq!(
            "0954edd5e0afe5542a4adf012611a91912a3ec16",
            hexify(&sha1(hexify(&private.value().to_bytes_be()).as_bytes()))
        );
    }
}
