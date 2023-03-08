/// # Convert hex to base64
///
/// <https://cryptopals.com/sets/1/challenges/1>
///
/// ## Notes
/// Basically, convert from hex -> binary -> base64
pub mod challenge_01;

/// # Fixed XOR
///
/// <https://cryptopals.com/sets/1/challenges/2>
///
/// ## Notes
/// See [crate::util::xor]
pub mod challenge_02;

/// # Single-byte XOR cipher
///
/// <https://cryptopals.com/sets/1/challenges/3>
///
/// ## Notes
/// Find the key to a ciphertext that has been xored against a single byte.
/// The reference, in the challenge, to ["ETAOIN
/// SHRDLU"](https://en.wikipedia.org/wiki/Etaoin_shrdlu) is supposed to be a clue that you should
/// use a frequency-scoring algorithm to guess what the plaintext letters are, and from that deduce
/// the key.
///
/// See [crate::cracking::find_single_byte_key]
pub mod challenge_03;

/// # Detect single-character XOR
///
/// <https://cryptopals.com/sets/1/challenges/4>
///
/// ## Notes
/// Iterate through the lines in the file, and find the one that has the highest score,
/// using the solution from challenge 3
pub mod challenge_04;

/// # Implement repeating-key XOR
///
/// <https://cryptopals.com/sets/1/challenges/5>
///
/// ## Notes
/// See [crate::cracking::repeating_key_xor]
pub mod challenge_05;

/// # Break repeating-key XOR
///
/// <https://cryptopals.com/sets/1/challenges/6>
///
/// ## Notes
/// See [crate::cracking::break_repeating_key_xor]
pub mod challenge_06;

/// # AES in ECB mode
///
/// <https://cryptopals.com/sets/1/challenges/7>
///
/// ## Notes
/// Decrypt a file encrypted with AES-128 and a key (which you're given)
pub mod challenge_07;

/// # Detect AES in ECB mode
///
/// <https://cryptopals.com/sets/1/challenges/8>
///
/// ## Notes
/// Detect which line in a file has been encrypted with AES-128 in ECB mode. Basically, look for
/// any repeating blocks, the [hallmark of ECB
/// mode](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_codebook_(ECB))
///
/// See [crate::ecb::detect_ecb]
pub mod challenge_08;
