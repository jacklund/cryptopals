use crate::util::{create_histogram, keystream_from_byte, try_xor_key};
use lazy_static::lazy_static;

pub mod aes;
mod challenges;
pub mod util;

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

pub fn repeating_key_xor(key: &[u8], plaintext: &[u8]) -> Vec<u8> {
    key.iter()
        .cycle()
        .take(plaintext.len())
        .zip(plaintext)
        .map(|(k, p)| k ^ p)
        .collect()
}

pub fn hamming_distance(a: &[u8], b: &[u8]) -> usize {
    a.iter()
        .zip(b)
        .fold(0u32, |sum, (a, b)| sum + (a ^ b).count_ones()) as usize
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

pub fn pkcs7_pad(plaintext: &[u8], blocksize: usize) -> Vec<u8> {
    let padding_size = (blocksize - (plaintext.len() % blocksize)) % blocksize;
    let mut vec = plaintext.to_vec();
    vec.extend(std::iter::repeat(padding_size as u8).take(padding_size));

    vec
}

pub fn pkcs7_unpad(plaintext: &[u8], blocksize: usize) -> Vec<u8> {
    let padding_value = plaintext[plaintext.len() - 1] as usize;
    if padding_value <= blocksize {
        plaintext[..plaintext.len() - padding_value].to_vec()
    } else {
        plaintext.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::*;

    pub const ICE_ICE_BABY: &str = "I'm back and I'm ringin' the bell \n\
        A rockin' on the mike while the fly girls yell \n\
        In ecstasy in the back of me \n\
        Well that's my DJ Deshay cuttin' all them Z's \n\
        Hittin' hard and the girlies goin' crazy \n\
        Vanilla's on the mike, man I'm not lazy. \n\
        \n\
        I'm lettin' my drug kick in \n\
        It controls my mouth and I begin \n\
        To just let it flow, let my concepts go \n\
        My posse's to the side yellin', Go Vanilla Go! \n\
        \n\
        Smooth 'cause that's the way I will be \n\
        And if you don't give a damn, then \n\
        Why you starin' at me \n\
        So get off 'cause I control the stage \n\
        There's no dissin' allowed \n\
        I'm in my own phase \n\
        The girlies sa y they love me and that is ok \n\
        And I can dance better than any kid n' play \n\
        \n\
        Stage 2 -- Yea the one ya' wanna listen to \n\
        It's off my head so let the beat play through \n\
        So I can funk it up and make it sound good \n\
        1-2-3 Yo -- Knock on some wood \n\
        For good luck, I like my rhymes atrocious \n\
        Supercalafragilisticexpialidocious \n\
        I'm an effect and that you can bet \n\
        I can take a fly girl and make her wet. \n\
        \n\
        I'm like Samson -- Samson to Delilah \n\
        There's no denyin', You can try to hang \n\
        But you'll keep tryin' to get my style \n\
        Over and over, practice makes perfect \n\
        But not if you're a loafer. \n\
        \n\
        You'll get nowhere, no place, no time, no girls \n\
        Soon -- Oh my God, homebody, you probably eat \n\
        Spaghetti with a spoon! Come on and say it! \n\
        \n\
        VIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \n\
        Intoxicating so you stagger like a wino \n\
        So punks stop trying and girl stop cryin' \n\
        Vanilla Ice is sellin' and you people are buyin' \n\
        'Cause why the freaks are jockin' like Crazy Glue \n\
        Movin' and groovin' trying to sing along \n\
        All through the ghetto groovin' this here song \n\
        Now you're amazed by the VIP posse. \n\
        \nSteppin' so hard like a German Nazi \n\
        Startled by the bases hittin' ground \n\
        There's no trippin' on mine, I'm just gettin' down \n\
        Sparkamatic, I'm hangin' tight like a fanatic \n\
        You trapped me once and I thought that \n\
        You might have it \n\
        So step down and lend me your ear \n\
        '89 in my time! You, '90 is my year. \n\
        \n\
        You're weakenin' fast, YO! and I can tell it \n\
        Your body's gettin' hot, so, so I can smell it \n\
        So don't be mad and don't be sad \n\
        'Cause the lyrics belong to ICE, You can call me Dad \n\
        You're pitchin' a fit, so step back and endure \n\
        Let the witch doctor, Ice, do the dance to cure \n\
        So come up close and don't be square \n\
        You wanna battle me -- Anytime, anywhere \n\
        \n\
        You thought that I was weak, Boy, you're dead wrong \n\
        So come on, everybody and sing this song \n\
        \n\
        Say -- Play that funky music Say, go white boy, go white boy go \n\
        play that funky music Go white boy, go white boy, go \n\
        Lay down and boogie and play that funky music till you die. \n\
        \n\
        Play that funky music Come on, Come on, let me hear \n\
        Play that funky music white boy you say it, say it \n\
        Play that funky music A little louder now \n\
        Play that funky music, white boy Come on, Come on, Come on \n\
        Play that funky music \n";

    #[test]
    fn test_hex() {
        let value: Vec<u8> = vec![163];
        assert_eq!(unhexify("a3").unwrap(), value);
        assert!(unhexify("x3").is_err());
        assert!(matches!(hexify(&[0xa3u8]).as_str(), "a3"));
    }

    #[test]
    fn test_base64() {
        assert_eq!(
            to_base64("Many hands make light work.".as_bytes()),
            "TWFueSBoYW5kcyBtYWtlIGxpZ2h0IHdvcmsu"
        );
    }

    #[test]
    fn test_hamming() {
        assert_eq!(
            37,
            hamming_distance("this is a test".as_bytes(), "wokka wokka!!!".as_bytes()),
        );
    }
}
