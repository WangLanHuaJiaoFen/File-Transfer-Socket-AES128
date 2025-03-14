use crate::aes::{
    add_round_key, inv_mix_columns, inv_shift_rows, inv_sub_bytes, mix_columns, shift_rows,
    sub_bytes,
};
use crate::key_expansion::key_expansion;

// 一维数组和状态矩阵的相互转换
fn array_to_state(array: &[u8; 16]) -> [[u8; 4]; 4] {
    let mut state = [[0u8; 4]; 4];
    for (i, byte) in array.iter().enumerate() {
        state[i % 4][i / 4] = *byte;
    }
    state
}

fn state_to_array(state: &[[u8; 4]; 4]) -> [u8; 16] {
    let mut array = [0u8; 16];
    for i in 0..16 {
        array[i] = state[i % 4][i / 4];
    }
    array
}

fn words_to_state(words: &[[u8; 4]]) -> [[u8; 4]; 4] {
    let mut round_key = [[0u8; 4]; 4];
    for col in 0..4 {
        for row in 0..4 {
            round_key[row][col] = words[col][row];
        }
    }
    round_key
}

pub fn aes_encrypt_block(block: &mut [u8; 16], key: &[u8; 16]) {
    // round_keys 按照行主序
    let round_keys = key_expansion(key);
    // state为列主序
    let mut state = array_to_state(&block);

    // 初始轮, round_keys[0..4];
    let initial_round_key = words_to_state(&round_keys[0..4]);
    // 轮密钥加
    add_round_key(&mut state, &initial_round_key);

    // 前9轮
    for round in 1..10 {
        sub_bytes(&mut state);
        shift_rows(&mut state);
        mix_columns(&mut state);
        let round_key = words_to_state(&round_keys[round * 4..(round + 1) * 4]);
        add_round_key(&mut state, &round_key);
    }

    // 最后一轮(不含MixColumns)
    sub_bytes(&mut state);
    shift_rows(&mut state);
    let final_round_key = words_to_state(&round_keys[40..44]);
    add_round_key(&mut state, &final_round_key);

    *block = state_to_array(&state);
}

pub fn aes_decrypt_block(block: &mut [u8; 16], key: &[u8; 16]) {
    // 先生成加密时的round_keys
    let round_keys = key_expansion(key);

    let mut state = array_to_state(&block);

    // 初始轮使用第11个密钥
    let round_key = words_to_state(&round_keys[40..44]);
    add_round_key(&mut state, &round_key);

    for round in (1..10).rev() {
        inv_shift_rows(&mut state);
        inv_sub_bytes(&mut state);
        let round_key = words_to_state(&round_keys[round * 4..(round + 1) * 4]);
        add_round_key(&mut state, &round_key);
        inv_mix_columns(&mut state);
    }

    inv_shift_rows(&mut state);
    inv_sub_bytes(&mut state);
    let round_key = words_to_state(&round_keys[0..4]);
    add_round_key(&mut state, &round_key);

    *block = state_to_array(&state);
}
