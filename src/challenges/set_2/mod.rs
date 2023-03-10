/// # Implement PKCS#7 padding
///
/// <https://cryptopals.com/sets/2/challenges/9>
///
/// ## Notes
/// Their explanation is pretty minimal, as usual. Better explanation
/// [here](https://node-security.com/posts/cryptography-pkcs-7-padding/)
///
/// See [crate::pkcs7]
pub mod challenge_09;

/// # Implement CBC mode
///
/// <https://cryptopals.com/sets/2/challenges/10>
///
/// ## Notes
/// Fairly straightforward
///
/// See [crate::cbc]
pub mod challenge_10;

/// # An ECB/CBC detection oracle
///
/// <https://cryptopals.com/sets/2/challenges/11>
///
/// ## Notes
/// We already know how to detect ECB, just do that, and if it's not that, it's CBC
///
/// See [crate::ecb::detect_ecb]
pub mod challenge_11;

/// # Byte-at-a-time ECB decryption (Simple)
///
/// <https://cryptopals.com/sets/2/challenges/12>
///
/// ## Notes
/// Their explanation of how to do this is, for a change, not terrible.
///
/// See [crate::ecb::byte_by_byte_ecb_decrypt]
pub mod challenge_12;

/// # ECB cut-and-paste
///
/// <https://cryptopals.com/sets/2/challenges/13>
///
/// ## Notes
/// Basically, you're just taking advantage of the fact that ECB doesn't mix in data from other
/// blocks. Create a fake email which has 'admin' at the end, push it until that part is across a
/// block boundary, and grab the encrypted block. Then, create another email, this time pushing
/// 'role=' to where the = is at the block boundary, and then just add your other block to the end.
/// Voila, 'role=admin'
pub mod challenge_13;
pub mod challenge_14;
pub mod challenge_15;
pub mod challenge_16;
