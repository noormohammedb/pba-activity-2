//! In Module 1, we discussed Block ciphers like AES. Block ciphers have a fixed length input.
//! Real wold data that we wish to encrypt _may_ be exactly the right length, but is probably not.
//! When your data is too short, you can simply pad it up to the correct length.
//! When your data is too long, you have some options.
//!
//! In this exercise, we will explore a few of the common ways that large pieces of data can be
//! broken up and combined in order to encrypt it with a fixed-length block cipher.
//!
//! WARNING: ECB MODE IS NOT SECURE.
//! Seriously, ECB is NOT secure. Don't use it irl. We are implementing it here to understand _why_
//! it is not secure and make the point that the most straight-forward approach isn't always the
//! best, and can sometimes be trivially broken.

use aes::{
    cipher::{generic_array::GenericArray, BlockCipher, BlockDecrypt, BlockEncrypt, KeyInit},
    Aes128,
};
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Ecb};
use rand::Rng;
use std::convert::TryInto;
use std::str::from_utf8;

///We're using AES 128 which has 16-byte (128 bit) blocks.
const BLOCK_SIZE: usize = 16;

fn main() {
    // todo!("Maybe this should be a library crate. TBD");
    // let plain_text = *b"Hello world!    ";
    // println!("Plaintext: {:?}", plain_text);
    // let key = b"an example key 1";
    // let cipher_text = aes_encrypt(plain_text, key); // Replace with actual encrypted data;

    // let decrypted = aes_decrypt(cipher_text, key);

    // println!("Decrypted: {:?}", decrypted);
    // let x = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17];
    // let pad_result = group(pad(x));
    // let saved_pad_result = pad_result.clone();
    // let unpad_result = un_pad(un_group(pad_result));

    // println!("pad: {:?}", saved_pad_result);
    // println!("unpad: {:?}", unpad_result);
}

/// Simple AES encryption
/// Helper function to make the core AES block cipher easier to understand.
fn aes_encrypt(data: [u8; BLOCK_SIZE], key: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    // Convert the inputs to the necessary data type
    let mut block = GenericArray::from(data);
    let key = GenericArray::from(*key);

    let cipher = Aes128::new(&key);

    cipher.encrypt_block(&mut block);

    block.into()
}

/// Simple AES encryption
/// Helper function to make the core AES block cipher easier to understand.
fn aes_decrypt(data: [u8; BLOCK_SIZE], key: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    // Convert the inputs to the necessary data type
    let mut block = GenericArray::from(data);
    let key = GenericArray::from(*key);

    let cipher = Aes128::new(&key);

    cipher.decrypt_block(&mut block);

    block.into()
}

/// Before we can begin encrypting our raw data, we need it to be a multiple of the
/// block length which is 16 bytes (128 bits) in AES128.
///
/// The padding algorithm here is actually not trivial. The trouble is that if we just
/// naively throw a bunch of zeros on the end, there is no way to know, later, whether
/// those zeros are padding, or part of the message, or some of each.
///
/// The scheme works like this. If the data is not a multiple of the block length,  we
/// compute how many pad bytes we need, and then write that number into the last several bytes.
/// Later we look at the last byte, and remove that number of bytes.
///
/// But if the data _is_ a multiple of the block length, then we have a problem. We don't want
/// to later look at the last byte and remove part of the data. Instead, in this case, we add
/// another entire block containing the block length in each byte. In our case,
/// [16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16]
fn pad(mut data: Vec<u8>) -> Vec<u8> {
    // When twe have a multiple the second term is 0
    let number_pad_bytes = BLOCK_SIZE - data.len() % BLOCK_SIZE;

    for _ in 0..number_pad_bytes {
        data.push(number_pad_bytes as u8);
    }

    data
}

/// Groups the data into BLOCK_SIZE blocks. Assumes the data is already
/// a multiple of the block size. If this is not the case, call `pad` first.
fn group(data: Vec<u8>) -> Vec<[u8; BLOCK_SIZE]> {
    let mut blocks = Vec::new();
    let mut i = 0;
    while i < data.len() {
        let mut block: [u8; BLOCK_SIZE] = Default::default();
        block.copy_from_slice(&data[i..i + BLOCK_SIZE]);
        blocks.push(block);

        i += BLOCK_SIZE;
    }
    blocks
}

/// Does the opposite of the group function
fn un_group(blocks: Vec<[u8; BLOCK_SIZE]>) -> Vec<u8> {
    let mut data = Vec::with_capacity(blocks.len() * BLOCK_SIZE);
    for block in blocks {
        data.extend_from_slice(&block);
    }
    data
}

/// Does the opposite of the pad function.
fn un_pad(data: Vec<u8>) -> Vec<u8> {
    // 1) get the last index of data: Vec
    // 2) get the value of that element n = data[i]
    // 3) remove the last n elements from data
    let mut new_vec = data.clone();
    let n_to_remove = data[data.len() - 1] as usize;
    new_vec.truncate(new_vec.len() - n_to_remove);
    new_vec
}

// Create an alias for the ECB mode using Aes128 with PKCS7 padding
type Aes128Ecb = Ecb<Aes128, Pkcs7>;

/// The first mode we will implement is the Electronic Code Book, or ECB mode.
/// Warning: THIS MODE IS NOT SECURE!!!!
///
/// This is probably the first thing you think of when considering how to encrypt
/// large data. In this mode we simply encrypt each block of data under the same key.
/// One good thing about this mode is that it is parallelizable. But to see why it is
/// insecure look at: https://www.ubiqsecurity.com/wp-content/uploads/2022/02/ECB2.png
fn ecb_encrypt(plain_text: Vec<u8>, key: [u8; 16]) -> Vec<u8> {
    let blocks = group(pad(plain_text));

    let mut cipher_blocks = Vec::new();

    for block in blocks {
        let encrypted_block = aes_encrypt(block, &key);
        cipher_blocks.push(encrypted_block)
    }
    cipher_blocks
        .iter()
        .flat_map(|block| block.clone())
        .collect::<Vec<u8>>()
}

/// Opposite of ecb_encrypt.
fn ecb_decrypt(cipher_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
    // Initialize the cipher with the key
    // let cipher = Aes128Ecb::new_var(&key, &[]).unwrap();
    //
    // // Decrypt the cipher_text
    // let decrypted_text = cipher.decrypt_vec(&cipher_text).unwrap();
    //
    // decrypted_text

    let mut plain_text_blocks = Vec::new();

    let padded_cipher_blocks = group(cipher_text);

    for block in padded_cipher_blocks {
        let decrypted_block = aes_decrypt(block, &key);
        plain_text_blocks.push(decrypted_block);
    }

    let plain_groups_paded = un_group(plain_text_blocks);
    let plain_text = un_pad(plain_groups_paded);

    plain_text
}

fn initialize_random_vector() -> [u8; BLOCK_SIZE] {
    let mut rng = rand::thread_rng();
    let mut arr: [u8; BLOCK_SIZE] = [0; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        arr[i] = rng.gen();
    }
    arr
}

fn xor(arr1: [u8; BLOCK_SIZE], arr2: [u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    let mut result: [u8; 16] = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        result[i] = arr1[i] ^ arr2[i];
    }
    result
}

/// The next mode, which you can implement on your own is cipherblock chaining.
/// This mode actually is secure, and it often used in real world applications.
///
/// In this mode, the ciphertext from the first block is XORed with the
/// plaintext of the next block before it is encrypted.
///
/// For more information, and a very clear diagram,
/// see https://de.wikipedia.org/wiki/Cipher_Block_Chaining_Mode
///
/// You will need to generate a random initialization vector (IV) to encrypt the
/// very first block because it doesn't have a previous block. Typically this IV
/// is inserted as the first block of ciphertext.
fn cbc_encrypt(plain_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
    // Remember to generate a random initialization vector for the first block.

    let mut cipher_text = Vec::new();
    // [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
    // [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
    // [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]

    let blocks = group(pad(plain_text));

    let initial_vector = initialize_random_vector();

    let mut i: usize = 0;
    let mut xor_input = initial_vector;

    while i < blocks.len() {
        let block = blocks[i];
        let result_xor = xor(xor_input, block);
        let cipher_out = aes_encrypt(result_xor, &key);
        cipher_text.extend_from_slice(&cipher_out);
        xor_input = cipher_out;
        i += 1;
    }
    let mut output_cipher_text = initial_vector.to_vec();
    output_cipher_text.extend_from_slice(&cipher_text);
    output_cipher_text
}

fn cbc_decrypt(cipher_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
    let cipher_blocks = group(cipher_text);

    let mut plain_text = Vec::new();
    let mut i = cipher_blocks.len() - 1;

    while i >= 1 {
        let cipher_block = cipher_blocks[i];
        let next_cipher_block = cipher_blocks[i - 1];
        let decrypted_result = aes_decrypt(cipher_block, &key);
        let plain_text_chunk = xor(decrypted_result, next_cipher_block);
        plain_text.push(plain_text_chunk);
        // append plain_text chunk to arr

        i -= 1;
    }
    plain_text.reverse(); // bc we appended from the end

    un_pad(un_group(plain_text))
}

/// Another mode which you can implement on your own is counter mode.
/// This mode is secure as well, and is used in real world applications.
/// It allows parallelized encryption and decryption, as well as random read access when decrypting.
///
/// In this mode, there is an index for each block being encrypted (the "counter"), as well as a random nonce.
/// For a 128-bit cipher, the nonce is 64 bits long.
///
/// For the ith block, the 128-bit value V of `nonce | counter` is constructed, where | denotes
/// concatenation. Then, V is encrypted with the key using ECB mode. Finally, the encrypted V is
/// XOR'd with the plaintext to produce the ciphertext.
///
/// A very clear diagram is present here:
/// https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)
///
/// Once again, you will need to generate a random nonce which is 64 bits long. This should be
/// inserted as the first block of the ciphertext.

fn ctr_encrypt(plain_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
    // Generate random 8 byte nonce
    let mut rng = rand::thread_rng();
    let nonce: [u8; 8] = rng.gen();
    // split plain text into 16 bytes blocks
    let blocks = group(pad(plain_text));

    // for each block concatenate once with counter value that starts with 0 and increments for each block
    let mut encrypted_blocks = Vec::new();

    for (i, block) in blocks.iter().enumerate() {
        // construct the counter value (nonce | counter)
        let mut counter_block = [0u8; BLOCK_SIZE];
        counter_block[..8].copy_from_slice(&nonce);
        counter_block[8..].copy_from_slice(&(i as u64).to_be_bytes());

        // encrypt the constructed value (nonce | counter) using AES encryption
        let encrypted_counter = aes_encrypt(counter_block, &key);

        // XOR the encrypted counter with the corresponding !plain text block
        let encrypted_block: [u8; BLOCK_SIZE] = xor(encrypted_counter, *block);

        encrypted_blocks.push(encrypted_block);
    }

    // concatenate the encrypted blocks and prepend the nonce
    let mut cipher_text = nonce.to_vec();
    cipher_text.extend_from_slice(&un_group(encrypted_blocks));
    cipher_text
}

fn ctr_decrypt(cipher_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
    // extract the nonce (first 8 bytes)
    let nonce: [u8; 8] = cipher_text[..8].try_into().unwrap();

    // split the ciphertext into 16 bytes blocks (excluding the nonce)
    let blocks = group(cipher_text[8..].to_vec());

    // decrypt each block using the counter mode
    let mut decrypted_blocks = Vec::new();

    // for each block
    for (i, block) in blocks.iter().enumerate() {
        // construct the counter value (nonce | counter)
        let mut counter_block = [0u8; BLOCK_SIZE];
        counter_block[..8].copy_from_slice(&nonce);
        counter_block[8..].copy_from_slice(&(i as u64).to_be_bytes());

        // encrypt the counter using AES (both encryption and decryption involve encrypting the counter)
        let encrypted_counter = aes_encrypt(counter_block, &key);

        // xor encrypter counter with the !ciphertext blocks
        let decrypted_block: [u8; BLOCK_SIZE] = xor(encrypted_counter, *block);

        decrypted_blocks.push(decrypted_block);
    }

    //concatenate decrypted blocks
    let decrypted_data = un_group(decrypted_blocks);

    //return unpadded crypted data
    un_pad(decrypted_data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ecb_encrypt() {
        let plain_text = "foo bar koo".as_bytes().to_vec();
        let my_key = [
            00, 01, 02, 03, 04, 05, 06, 07, 08, 09, 10, 11, 12, 13, 14, 15,
        ];

        let encrypted_data = ecb_encrypt(plain_text.clone(), my_key);

        assert_ne!(encrypted_data, plain_text);

        let decrypted_data = ecb_decrypt(encrypted_data, my_key);

        assert_eq!(decrypted_data, plain_text);
    }

    #[test]
    fn test_ecb_decrypt() {
        let plain_text = "lorem ipsum".as_bytes().to_vec();

        let my_key = [
            00, 01, 02, 03, 04, 05, 06, 07, 08, 09, 10, 11, 12, 13, 14, 15,
        ];

        let encrypted_data = ecb_encrypt(plain_text.clone(), my_key);

        let decrypted_data = ecb_decrypt(encrypted_data, my_key);

        assert_eq!(decrypted_data, plain_text);
    }

    #[test]
    fn test_ctr_encrypt_decrypt() {
        // define key for encryption/decryption
        let key = [0x00; BLOCK_SIZE]; // array of 16 bytes

        // define a plain text message to be encrypted
        let plain_text = b"Hello, AES in CTR mode! This is a test.".to_vec();

        // encrypt plain text using CTR mode
        let encrypted_text = ctr_encrypt(plain_text.clone(), key);

        // check that the encrypted text is different from the plain text
        assert_ne!(encrypted_text, plain_text);

        // decrypt the encrypted text using CTR mode
        let decrypted_text = ctr_decrypt(encrypted_text, key);

        // check that the decrypted text matches the original plain text
        assert_eq!(decrypted_text, plain_text);
    }

    #[test]
    fn test_cbc_encrypt_decrypt() {
        let input = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17];

        let key = b"somekeyofsize123";

        let encrypted_result = cbc_encrypt(input.clone(), *key);

        let decrypted_result = cbc_decrypt(encrypted_result, *key);

        println!("Decrypted Result: {:?}", decrypted_result);

        assert_eq!(&input, &decrypted_result);
    }
}
