use crate::table::{AES_SBOX, RCON};
// 密钥扩展
fn rot_word(word: [u8; 4]) -> [u8; 4] {
    [word[1], word[2], word[3], word[0]]
}

fn sub_word(word: [u8; 4]) -> [u8; 4] {
    [
        AES_SBOX[word[0] as usize],
        AES_SBOX[word[1] as usize],
        AES_SBOX[word[2] as usize],
        AES_SBOX[word[3] as usize],
    ]
}



pub fn key_expansion(key: &[u8; 16]) -> [[u8; 4]; 44] {
    let mut round_keys = [[0u8; 4]; 44];

    // 前16个字节 = 原始密钥
    for i in 0..4 {
        let start = i * 4;
        round_keys[i] = [
            key[start],
            key[start + 1], 
            key[start + 2], 
            key[start + 3]
        ];
    }

    // 生成w[4..44]
    for i in 4..44 {
        // 可能会修改m[i - 1]
        let mut temp = round_keys[i - 1];

        if i % 4 == 0 {
            // 计算g(m[i - 1])
            temp = sub_word(rot_word(temp));
            temp[0] ^= RCON[(i / 4) - 1];
        }

        round_keys[i] = [
            round_keys[i - 4][0] ^ temp[0], 
            round_keys[i - 4][1] ^ temp[1], 
            round_keys[i - 4][2] ^ temp[2], 
            round_keys[i - 4][3] ^ temp[3], 
        ];
    }
    
    round_keys
}
