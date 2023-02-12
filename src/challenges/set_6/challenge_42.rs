#[cfg(test)]
mod tests {
    use crate::digest::{sha1::*, Digest};
    use crate::rsa::*;
    use num::One;
    use num_bigint::*;

    #[test]
    fn challenge_42() {
        let bitsize = 1024;
        let (_, pubkey) = generate_keypair(bitsize);

        // Hash the message
        let plaintext = "hi mom".as_bytes();
        let mut hasher = SHA1::new();
        hasher.update(plaintext);
        let hash = hasher.digest().to_vec();

        // Generate the ASN.1
        let asn_1 = asn1::write_single(&DigestInfo::new(SHA1::OID, &hash)).unwrap();

        // Minimal signature
        let mut signature_bytes = vec![0, 1, 0xff, 0];
        signature_bytes.extend(asn_1.to_vec());
        signature_bytes.extend(
            std::iter::repeat(0)
                .take(pubkey.byte_length() - signature_bytes.len())
                .collect::<Vec<u8>>(),
        );

        // Generate forged signature by taking the cube root of the "signature"
        let value = BigUint::from_bytes_be(&signature_bytes);
        let mut root = value.cbrt();

        // Find a cube root which, when cubed, is >= our value
        while root.pow(3) < value {
            root += BigUint::one();
        }
        let forged = root.to_bytes_be();

        // Verify the signature using someone's public key
        assert!(bad_verify::<SHA1>(&pubkey, plaintext, &forged));
    }
}