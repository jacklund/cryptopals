#[cfg(test)]
mod tests {
    use crate::cbc::*;
    use crate::pkcs7::Serialize;
    use crate::util::*;

    #[test]
    fn challenge_50() {
        let blocksize = 16;
        let key = "YELLOW SUBMARINE".as_bytes();
        let iv = std::iter::repeat(0u8).take(blocksize).collect::<Vec<u8>>();

        // Verify that all is well with the original
        let original = "alert('MZA who was that?');\n";
        let mac = cbc_mac(key, &iv, original.as_bytes(), blocksize);
        assert!(cbc_mac_verify(
            key,
            &iv,
            original.as_bytes(),
            &mac,
            blocksize
        ));
        assert_eq!("296b8d7cb78a243dda4d0a61d33bbdd1", hexify(&mac));

        // Change the javascript
        let changed = "alert('Ayo, the Wu is back!);\n";
        let changed_mac = cbc_mac(key, &iv, changed.as_bytes(), blocksize);

        // Pad the forged javascript
        let padded = changed.as_bytes().pkcs7_serialize(blocksize);
        let mut forged = padded.to_vec();

        // Append the xor of the first original block with the mac of the changed block
        // This will give us a mac that matches the original block's
        let forged_block = xor(&original.as_bytes()[..blocksize], &changed_mac).unwrap();
        forged.extend_from_slice(&forged_block);

        // Add the rest of the original block to round out the mac
        forged.extend(original[blocksize..].as_bytes());

        // Ta-da!
        let forged_mac = cbc_mac(key, &iv, &forged, blocksize);
        assert_eq!(mac, forged_mac);
    }
}
