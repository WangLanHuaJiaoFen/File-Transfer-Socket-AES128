use crate::block::{aes_decrypt_block, aes_encrypt_block};
use base64::{engine::general_purpose, Engine as _};

fn pkcs7_pad(data: &[u8]) -> Vec<u8> {
    // 求填充长度
    // 如果已经是16的整数倍，则填充16字节的16，
    let pad_len = 16 - (data.len() % 16);
    let mut padded = data.to_vec();

    padded.extend(vec![pad_len as u8; pad_len]);
    padded
}

pub fn aes_ecb_encrypt(plaintext: &[u8], key: &[u8; 16]) -> Vec<u8> {
    // 填充
    let padded_plaintext = pkcs7_pad(plaintext);
    let mut ciphertext = Vec::with_capacity(padded_plaintext.len());

    for chunk in padded_plaintext.chunks_exact(16) {
        let mut block = [0u8; 16];
        block.copy_from_slice(chunk);
        aes_encrypt_block(&mut block, key);
        ciphertext.extend_from_slice(&block);
    }

    ciphertext
}

fn pkcs7_unpad(data: &[u8]) -> Vec<u8> {
    if let Some(&pad_len) = data.last() {
        // 判断最后一个字节是不是填充长度
        // data[data.len() - pad_len as usize..]是开始填充的第一位在data中的下标
        // data[..data.len() - pad_len as usize]是从头到填充的第一位之前一位
        if pad_len as usize <= data.len()
            && data[data.len() - pad_len as usize..]
                .iter()
                .all(|&b| b == pad_len)
        {
            return data[..data.len() - pad_len as usize].to_vec();
        }
    }
    panic!("wrong");
}

pub fn aes_ecb_decrypt(ciphertext: &[u8], key: &[u8; 16]) -> Vec<u8> {
    let mut plaintext = Vec::with_capacity(ciphertext.len());

    for chunk in ciphertext.chunks_exact(16) {
        let mut block = [0u8; 16];
        block.copy_from_slice(chunk);
        aes_decrypt_block(&mut block, key);
        plaintext.extend_from_slice(&block);
    }
    pkcs7_unpad(&plaintext)
}

pub fn aes_ecb_encrypt_string(plaintext: &str, key: &[u8; 16]) -> String {
    let plaintext_bytes = plaintext.as_bytes();
    let ciphertext = aes_ecb_encrypt(plaintext_bytes, key);
    general_purpose::STANDARD.encode(&ciphertext)
}

pub fn aes_ecb_decrypt_string(ciphertext_base64: &str, key: &[u8; 16]) -> String {
    let ciphertext = general_purpose::STANDARD
        .decode(ciphertext_base64)
        .expect("Base64 解码失败");

    let plaintext_bytes = aes_ecb_decrypt(&ciphertext, key);

    String::from_utf8(plaintext_bytes).expect("解密后不是有效的UTF-8")
}
