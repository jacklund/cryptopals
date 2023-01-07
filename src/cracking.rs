use crate::util::{create_histogram, hamming_distance, keystream_from_byte, try_xor_key};
use lazy_static::lazy_static;

lazy_static! {
    static ref CHAR_LIST_BY_FREQUENCY: Vec<u8> = {
        " etaoinshrdlu"
            .bytes()
            .flat_map(|b| {
                if b as char == ' ' {
                    vec![b]
                } else {
                    vec![
                        b,
                        (b as char).to_uppercase().collect::<Vec<char>>()[0] as u8,
                    ]
                }
            })
            .collect()
    };
}

pub fn repeating_key_xor(key: &[u8], plaintext: &[u8]) -> Vec<u8> {
    key.iter()
        .cycle()
        .take(plaintext.len())
        .zip(plaintext)
        .map(|(k, p)| k ^ p)
        .collect()
}

pub fn find_single_byte_key(ciphertext: &[u8]) -> (u8, usize, String) {
    let histogram = create_histogram(ciphertext);
    let ciphertext_val = histogram[0].0;

    // Since p ^ k = c, where p is the plaintext char, k is the key char, and c is the
    // ciphertext char, we can use k = c ^ p. Here, we take the most frequent char in the
    // ciphertext, and xor it with each of the most frequent chars in the English language,
    // and try that as a key. The key that gives us the highest score wins.
    CHAR_LIST_BY_FREQUENCY.iter().fold(
        (0u8, 0usize, String::new()),
        |(last_key, last_score, last_plaintext), b| {
            let key = *b ^ ciphertext_val;
            let (score, plaintext) = try_xor_key(
                &keystream_from_byte(*b ^ ciphertext_val, ciphertext.len()),
                ciphertext,
            );
            if score > last_score {
                (key, score, plaintext)
            } else {
                (last_key, last_score, last_plaintext)
            }
        },
    )
}

pub fn break_repeating_key_xor(ciphertext: &[u8]) -> (Vec<u8>, Vec<u8>) {
    // Iterate through various keysizes, chunking the ciphertext into keysize chunks,
    // and find the least average distance between the even and odd chunks
    // That will determine our key size
    let (_distance, keysize) = (2..40).fold(
        (1000f32, 1usize),
        |(last_distance, last_keysize), keysize| {
            // Chunk the ciphertext
            let (odd, even): (Vec<(usize, &[u8])>, Vec<(usize, &[u8])>) = ciphertext
                .chunks(keysize)
                .enumerate()
                .partition(|(i, _chunk)| i % 2 == 0);

            // Compute the average distance
            // This is average distance divided by key length.
            // Since average distance = total distance / number of samples,
            // and number of samples = string length / key length,
            // we end up with average distance = total distance / string length
            let average_distance = odd
                .iter()
                .zip(even)
                .map(|((_, odd_chunk), (_, even_chunk))| hamming_distance(odd_chunk, even_chunk))
                .sum::<usize>() as f32
                / ciphertext.len() as f32;
            if average_distance < last_distance {
                (average_distance, keysize)
            } else {
                (last_distance, last_keysize)
            }
        },
    );

    // Now that we have the key size, chunk the ciphertext in keysize chunks, and then transpose it
    // by taking the first byte of each chunk, then the second, etc. This leaves us with a bunch of
    // single-byte-encrypted ciphertexts.
    let mut nested_vecs: Vec<Vec<u8>> = Vec::new();
    (0..keysize).for_each(|_| nested_vecs.push(Vec::new()));
    let nested_vecs = ciphertext
        .chunks(keysize)
        .fold(nested_vecs, |mut nested_vecs, chunk| {
            chunk
                .iter()
                .enumerate()
                .for_each(|(i, b)| nested_vecs[i].push(*b));

            nested_vecs
        });

    // We find the single-byte key for each transposed ciphertext, and combine each of those into
    // our overall key
    let key = nested_vecs
        .iter()
        .map(|ciphertext| {
            let (key, _score, _plaintext) = find_single_byte_key(ciphertext);
            key
        })
        .collect::<Vec<u8>>();

    // ...and we decrypt
    let plaintext = repeating_key_xor(&key, ciphertext);

    (key, plaintext)
}
