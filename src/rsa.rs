use crate::digest::Digest;
use anyhow::{Error, Result};
use asn1::{Asn1Read, Asn1Write, ObjectIdentifier};
use num::One;
use num_bigint::*;
use num_modular::ModularUnaryOps;
use num_prime::RandPrime;
use rand::{self, Rng};
use std::collections::VecDeque;

// const MD2_OID: ObjectIdentifier = oid!(1, 2, 840, 113549, 2, 2);
// const MD4_OID: ObjectIdentifier = oid!(1, 2, 840, 113549, 2, 3);
// const MD5_OID: ObjectIdentifier = oid!(1, 2, 840, 113549, 2, 5);
// const SHA1_OID: ObjectIdentifier = oid!(1, 3, 14, 3, 2, 26);
// const SHA224_OID: ObjectIdentifier = oid!(2, 16, 840, 1, 101, 3, 4, 2, 4);
// const SHA256_OID: ObjectIdentifier = oid!(2, 16, 840, 1, 101, 3, 4, 2, 1);
// const SHA384_OID: ObjectIdentifier = oid!(2, 16, 840, 1, 101, 3, 4, 2, 2);
// const SHA512_OID: ObjectIdentifier = oid!(2, 16, 840, 1, 101, 3, 4, 2, 3);

enum OperationType {
    Encryption,
    Signature,
}

#[derive(Asn1Read, Asn1Write, Debug)]
pub struct DigestInfo<'a> {
    digest_algorithm: ObjectIdentifier,
    digest: &'a [u8],
}

impl<'a> DigestInfo<'a> {
    pub fn new(oid: ObjectIdentifier, digest: &'a [u8]) -> Self {
        Self {
            digest_algorithm: oid,
            digest,
        }
    }
}

#[derive(Clone, Debug)]
pub struct PublicKey {
    pub modulus: BigUint,
    pub exponent: BigUint,
}

#[derive(Clone, Debug)]
pub struct PrivateKey {
    pub modulus: BigUint,
    pub exponent: BigUint,
    pub public_key: PublicKey,
    pub primes: (BigUint, BigUint),
}

impl PublicKey {
    pub fn new(modulus: &BigUint, exponent: &BigUint) -> Self {
        Self {
            modulus: modulus.clone(),
            exponent: exponent.clone(),
        }
    }

    pub fn byte_length(&self) -> usize {
        (self.modulus.bits() as usize + 7) / 8
    }
}

impl PrivateKey {
    pub fn new(
        modulus: &BigUint,
        exponent: &BigUint,
        public_key: &PublicKey,
        p: &BigUint,
        q: &BigUint,
    ) -> Self {
        Self {
            modulus: modulus.clone(),
            exponent: exponent.clone(),
            public_key: public_key.clone(),
            primes: (p.clone(), q.clone()),
        }
    }

    pub fn byte_length(&self) -> usize {
        (self.modulus.bits() as usize + 7) / 8
    }
}

pub fn generate_keypair(bit_size: usize) -> (PrivateKey, PublicKey) {
    // We loop until we get a p, q pair that will let us generate our d value correctly
    // Tried using "gen_safe_prime()", which worked, but was really slow. This speeds it up
    // considerably
    loop {
        let p: BigUint = rand::thread_rng().gen_prime(bit_size / 2, None);
        let q: BigUint = rand::thread_rng().gen_prime(bit_size - p.bits() as usize, None);

        // Avoid where p is equal to q
        if p == q {
            continue;
        }

        let n = p.clone() * q.clone();

        // Make sure we have the right bit size
        if n.bits() != bit_size as u64 {
            continue;
        }
        let et = (p.clone() - BigUint::one()) * (q.clone() - BigUint::one());
        let e = BigUint::from(3u32);
        let d: Option<BigUint> = e.clone().invm(&et);

        if d.is_none() {
            continue;
        }

        let public_key = PublicKey::new(&n, &e);
        let private_key = PrivateKey::new(&n, &d.unwrap(), &public_key, &p, &q);
        return (private_key, public_key);
    }
}

// PKCS1 v1.5 padding
fn pad(operation_type: OperationType, modulus_bytes: usize, data: &[u8]) -> Result<Vec<u8>> {
    if data.len() > modulus_bytes - 11 {
        return Err(Error::msg("Message too long"));
    }

    let padding_length = modulus_bytes - data.len() - 3;
    let mut output: Vec<u8> = Vec::with_capacity(modulus_bytes);
    output.push(0);
    match operation_type {
        OperationType::Encryption => {
            // Block type
            output.push(2);

            for _ in 0..padding_length {
                output.push(rand::thread_rng().gen_range(1..0xff));
            }
            output.push(0);
        }
        OperationType::Signature => {
            output.push(1); // Block type
            output.extend(
                std::iter::repeat(0xff)
                    .take(padding_length)
                    .collect::<Vec<u8>>(),
            );
            output.push(0);
        }
    }

    output.extend_from_slice(data);

    Ok(output)
}

fn unpad(operation_type: OperationType, data: &[u8]) -> Result<Vec<u8>> {
    println!("unpadding data: {:?}", data);
    let mut data: VecDeque<u8> = VecDeque::from(data.to_vec());
    match data.pop_front() {
        Some(0) => (),
        bad_value => {
            println!("Got bad first byte value {:?}", bad_value);
            return Err(Error::msg("Bad padding"));
        }
    }
    match operation_type {
        OperationType::Encryption => {
            match data.pop_front() {
                Some(2) => (),
                value => {
                    println!("Got {:?} as operation type, expected 2", value);
                    return Err(Error::msg("Bad padding"));
                }
            }
            loop {
                match data.pop_front() {
                    Some(0) => break,
                    Some(_) => (),
                    None => {
                        println!("Ran out of data in padding");
                        return Err(Error::msg("Bad padding"));
                    }
                }
            }
            Ok(data.iter().copied().collect())
        }
        OperationType::Signature => {
            match data.pop_front() {
                Some(1) => (),
                value => {
                    println!("Got {:?} as operation type, expected 1", value);
                    return Err(Error::msg("Bad padding"));
                }
            }
            loop {
                match data.pop_front() {
                    Some(0) => break,
                    Some(0xff) => (),
                    value => {
                        println!("Expected padding of 0xff, got {:?}", value);
                        return Err(Error::msg("Bad padding"));
                    }
                }
            }
            Ok(data.iter().copied().collect())
        }
    }
}

// Left pad our data with zeroes. When we encrypt/decrypt byte streams, the leading bytes might be
// zeroes, which will get lost when the bytes get converted to BigUint, so we pad out to the left
// to compensate
pub fn left_pad(data: &[u8], length: usize) -> Result<Vec<u8>> {
    if data.len() > length {
        Err(Error::msg("Invalid padding length"))
    } else {
        let mut output = vec![0; length - data.len()];
        output.extend_from_slice(data);
        Ok(output)
    }
}

// Encrypt without the PKCS 1.5 padding
pub fn encrypt_without_padding(key: &PublicKey, plaintext: &[u8]) -> Result<Vec<u8>> {
    let msg_uint = BigUint::from_bytes_be(plaintext);
    if msg_uint > key.modulus {
        return Err(Error::msg("Message is larger than the key modulus"));
    }
    println!("Encrypting {:?}", plaintext);
    left_pad(
        &msg_uint
            .modpow(&key.exponent, &key.modulus)
            .to_bytes_be()
            .to_vec(),
        key.byte_length(),
    )
}

// Encrypt with the padding
pub fn encrypt(key: &PublicKey, plaintext: &[u8]) -> Result<Vec<u8>> {
    encrypt_without_padding(
        key,
        &pad(OperationType::Encryption, key.byte_length(), plaintext)?,
    )
}

// Decrypt without the padding
pub fn decrypt_without_padding(key: &PrivateKey, ciphertext: &[u8]) -> Result<Vec<u8>> {
    let msg_uint = BigUint::from_bytes_be(ciphertext);
    if msg_uint > key.modulus {
        return Err(Error::msg("Message is larger than the key modulus"));
    }
    left_pad(
        &msg_uint
            .modpow(&key.exponent, &key.modulus)
            .to_bytes_be()
            .to_vec(),
        key.byte_length(),
    )
}

// Decrypt
pub fn decrypt(key: &PrivateKey, ciphertext: &[u8]) -> Result<Vec<u8>> {
    unpad(
        OperationType::Encryption,
        &decrypt_without_padding(key, ciphertext)?,
    )
}

pub fn sign<T>(key: &PrivateKey, message: &[u8]) -> Result<Vec<u8>>
where
    T: Digest,
{
    let mut hasher = T::new();
    hasher.update(message);
    let hash = hasher.digest().to_vec();
    let asn_1 = asn1::write_single(&DigestInfo::new(T::OID, &hash)).unwrap();
    let padded = pad(OperationType::Signature, key.byte_length(), &asn_1)?;
    println!("Padded signature = {:?}", padded);
    decrypt_without_padding(key, &padded)
}

// The broken verify algoritm needed for Challenge 42 (Bleichenbacher's attack)
// Surprisingly difficult, because the asn1 library does the right thing and fails the parse if
// there's extra garbage at the end. I had to isolate just the "asn.1" part, and validate that.
pub fn bad_verify<T>(key: &PublicKey, message: &[u8], signature: &[u8]) -> bool
where
    T: Digest,
{
    let signature_bytes = match encrypt_without_padding(key, signature) {
        Ok(bytes) => bytes,
        Err(error) => {
            println!("Got error from encrypt: {}", error);
            return false;
        }
    };
    println!("signature bytes = {:?}", signature_bytes);
    let unpadded = match unpad(OperationType::Signature, &signature_bytes) {
        Ok(bytes) => bytes,
        Err(error) => {
            println!("Got error from unpad: {}", error);
            return false;
        }
    };
    let digest_len = unpadded[1] as usize + 2;
    let digest_info = match asn1::parse_single::<DigestInfo>(&unpadded[..digest_len]) {
        Ok(info) => info,
        Err(error) => {
            println!("Error parsing asn1: {}", error);
            return false;
        }
    };
    println!("Digest info = {:?}", digest_info);

    if digest_info.digest_algorithm != T::OID {
        println!(
            "Got the wrong digest algorithm {}, was expecting {}",
            digest_info.digest_algorithm,
            T::OID
        );
        return false;
    }
    let mut hasher = T::new();
    hasher.update(message);
    let hash = hasher.digest().to_vec();
    println!("Hash = {:?}", hash);
    println!("digest = {:?}", digest_info.digest);
    hash == digest_info.digest
}

pub fn verify<T>(key: &PublicKey, message: &[u8], signature: &[u8]) -> bool
where
    T: Digest,
{
    let signature_bytes = match encrypt_without_padding(key, signature) {
        Ok(bytes) => bytes,
        Err(error) => {
            println!("Got error from encrypt: {}", error);
            return false;
        }
    };
    println!("signature bytes = {:?}", signature_bytes);
    let unpadded = match unpad(OperationType::Signature, &signature_bytes) {
        Ok(bytes) => bytes,
        Err(error) => {
            println!("Got error from unpad: {}", error);
            return false;
        }
    };
    let digest_info = match asn1::parse_single::<DigestInfo>(&unpadded) {
        Ok(info) => info,
        Err(error) => {
            println!("Error parsing asn1: {}", error);
            return false;
        }
    };
    println!("Digest info = {:?}", digest_info);

    if digest_info.digest_algorithm != T::OID {
        return false;
    }
    let mut hasher = T::new();
    hasher.update(message);
    let hash = hasher.digest().to_vec();
    hash == digest_info.digest
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::digest::sha256::Sha256;
    use num_modular::ModularUnaryOps;

    #[test]
    fn test_modinv() {
        assert_eq!(
            BigInt::from(1969),
            BigUint::from(42u32)
                .invm(&BigUint::from(2017u32))
                .unwrap()
                .into()
        );
    }

    #[test]
    fn test_rsa() {
        let bits = 512;
        let (private_key, public_key) = generate_keypair(bits);

        let data = b"hello world";
        let ciphertext = encrypt(&public_key, data).unwrap();
        let plaintext = decrypt(&private_key, &ciphertext).unwrap();
        assert_eq!(data, plaintext.as_slice());
    }

    #[test]
    fn test_signing() {
        let bits = 512;
        let (private_key, public_key) = generate_keypair(bits);

        // Sign
        let data = b"hello world";
        let signature = sign::<Sha256>(&private_key, data).unwrap();
        assert!(verify::<Sha256>(&public_key, data, &signature));
    }
}
