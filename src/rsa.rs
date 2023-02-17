use crate::digest::Digest;
use asn1::{Asn1Read, Asn1Write, ObjectIdentifier};
use num::{One, Zero};
use num_bigint::*;
use num_modular::ModularUnaryOps;
use num_prime::RandPrime;
use rand::{self, Rng};
use std::collections::VecDeque;
use thiserror::Error;

// Errors
#[derive(Error, Debug)]
pub enum Error {
    #[error("Message too long")]
    MessageTooLong,

    #[error("Bad padding")]
    BadPadding,

    #[error("Invalid padding length")]
    InvalidLength,
}

pub type Result<T> = std::result::Result<T, Error>;

// Trait for a PKCS1 1.5 padding type
pub trait PaddingType {
    const BLOCK_TYPE: u8;

    fn new(size: usize, data_size: usize) -> Self;

    fn check_size(&self) -> Result<()>;

    fn padding(&self) -> Vec<u8>;

    fn unpad(data: &mut VecDeque<u8>) -> Result<()>;
}

// PKCS1 1.5 encryption padding type
struct EncryptionPadding {
    size: usize,
    data_size: usize,
}

impl PaddingType for EncryptionPadding {
    const BLOCK_TYPE: u8 = 2;

    fn new(size: usize, data_size: usize) -> Self {
        Self { size, data_size }
    }

    // Encryption padding must be at least 8 bytes
    fn check_size(&self) -> Result<()> {
        if self.data_size > self.size - 11 {
            return Err(Error::MessageTooLong);
        }

        Ok(())
    }

    // Pad with pseudorandom bytes
    fn padding(&self) -> Vec<u8> {
        let padding_length = self.size - self.data_size - 3;
        let mut output: Vec<u8> = Vec::with_capacity(padding_length);
        for _ in 0..padding_length {
            output.push(rand::thread_rng().gen_range(1..0xff));
        }

        output
    }

    // Unpad
    fn unpad(data: &mut VecDeque<u8>) -> Result<()> {
        match data.pop_front() {
            Some(2) => (),
            value => {
                println!("Got {:?} as operation type, expected 2", value);
                return Err(Error::BadPadding);
            }
        }
        loop {
            match data.pop_front() {
                Some(0) => break Ok(()),
                Some(_) => (),
                None => {
                    println!("Ran out of data in padding");
                    return Err(Error::BadPadding);
                }
            }
        }
    }
}

// PKCS1 1.5 signature padding type
struct SignaturePadding {
    size: usize,
    data_size: usize,
}

impl PaddingType for SignaturePadding {
    const BLOCK_TYPE: u8 = 1;

    fn new(size: usize, data_size: usize) -> Self {
        Self { size, data_size }
    }

    fn check_size(&self) -> Result<()> {
        if self.data_size > self.size - 3 {
            return Err(Error::MessageTooLong);
        }

        Ok(())
    }

    // Pad with 0xff
    fn padding(&self) -> Vec<u8> {
        let padding_length = self.size - self.data_size - 3;

        vec![0xff; padding_length]
    }

    // Unpad
    fn unpad(data: &mut VecDeque<u8>) -> Result<()> {
        match data.pop_front() {
            Some(1) => (),
            value => {
                println!("Got {:?} as operation type, expected 2", value);
                return Err(Error::BadPadding);
            }
        }
        loop {
            match data.pop_front() {
                Some(0) => break Ok(()),
                Some(0xff) => (),
                value => {
                    println!("Expected padding of 0xff, got {:?}", value);
                    return Err(Error::BadPadding);
                }
            }
        }
    }
}

// Pad using PKCS1 1.5 padding of the given type
pub fn pad<T>(size: usize, data: &[u8]) -> Result<Vec<u8>>
where
    T: PaddingType,
{
    let padder = T::new(size, data.len());
    padder.check_size()?;

    let mut output: Vec<u8> = Vec::with_capacity(size);

    // Leading zero
    output.push(0);

    // Block type
    output.push(T::BLOCK_TYPE);

    // Nonzero pseudorandom bytes
    output.extend(padder.padding());

    // End of padding
    output.push(0);

    output.extend_from_slice(data);

    Ok(output)
}

// Unpad using PKCS1 1.5 padding of the given type
pub fn unpad<T>(data: &[u8]) -> Result<Vec<u8>>
where
    T: PaddingType,
{
    let mut data: VecDeque<u8> = VecDeque::from(data.to_vec());
    match data.pop_front() {
        Some(0) => (),
        _ => {
            return Err(Error::BadPadding);
        }
    }
    T::unpad(&mut data)?;
    Ok(data.iter().copied().collect())
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

// Left pad our data with zeroes. When we encrypt/decrypt byte streams, the leading bytes might be
// zeroes, which will get lost when the bytes get converted to BigUint, so we pad out to the left
// to compensate
pub fn left_pad(data: &[u8], length: usize) -> Result<Vec<u8>> {
    if data.len() > length {
        Err(Error::InvalidLength)
    } else {
        let mut output = vec![0; length - data.len()];
        output.extend_from_slice(data);
        Ok(output)
    }
}

pub fn encrypt_uint(key: &PublicKey, plaintext: &BigUint) -> Result<BigUint> {
    if *plaintext > key.modulus {
        Err(Error::MessageTooLong)
    } else {
        Ok(plaintext.modpow(&key.exponent, &key.modulus))
    }
}

// Encrypt without the PKCS 1.5 padding
pub fn encrypt_without_padding(key: &PublicKey, plaintext: &[u8]) -> Result<Vec<u8>> {
    let msg_uint = BigUint::from_bytes_be(plaintext);
    left_pad(
        &encrypt_uint(key, &msg_uint)?.to_bytes_be(),
        key.byte_length(),
    )
}

// Encrypt with the padding
pub fn encrypt(key: &PublicKey, plaintext: &[u8]) -> Result<Vec<u8>> {
    encrypt_without_padding(
        key,
        &pad::<EncryptionPadding>(key.byte_length(), plaintext)?,
    )
}

pub fn decrypt_uint(key: &PrivateKey, ciphertext: &BigUint) -> BigUint {
    ciphertext.modpow(&key.exponent, &key.modulus)
}

// Decrypt without the padding
pub fn decrypt_without_padding(key: &PrivateKey, ciphertext: &[u8]) -> Result<Vec<u8>> {
    left_pad(
        &decrypt_uint(key, &BigUint::from_bytes_be(ciphertext)).to_bytes_be(),
        key.byte_length(),
    )
}

// Decrypt
pub fn decrypt(key: &PrivateKey, ciphertext: &[u8]) -> Result<Vec<u8>> {
    unpad::<EncryptionPadding>(&decrypt_without_padding(key, ciphertext)?)
}

pub fn sign<T>(key: &PrivateKey, message: &[u8]) -> Result<Vec<u8>>
where
    T: Digest,
{
    let mut hasher = T::new();
    hasher.update(message);
    let hash = hasher.digest().to_vec();
    let asn_1 = asn1::write_single(&DigestInfo::new(T::OID, &hash)).unwrap();
    let padded = pad::<SignaturePadding>(key.byte_length(), &asn_1)?;
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
    let unpadded = match unpad::<SignaturePadding>(&signature_bytes) {
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
    let unpadded = match unpad::<SignaturePadding>(&signature_bytes) {
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

pub fn is_even_oracle(private_key: &PrivateKey, ciphertext: &[u8]) -> bool {
    BigUint::from_bytes_be(&decrypt_without_padding(private_key, ciphertext).unwrap())
        % BigUint::from(2u32)
        == BigUint::zero()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::digest::sha256::SHA256;
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
        let signature = sign::<SHA256>(&private_key, data).unwrap();
        assert!(verify::<SHA256>(&public_key, data, &signature));
    }
}
