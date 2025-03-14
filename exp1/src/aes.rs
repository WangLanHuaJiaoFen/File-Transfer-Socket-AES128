use crate::table::{AES_SBOX, INVERSE_AES_SBOX};

// SubBytes
pub fn sub_bytes(state: &mut [[u8; 4]; 4]) {
    for row in state.iter_mut() {
        for byte in row.iter_mut() {
            *byte = AES_SBOX[*byte as usize];
        }
    }
}

pub fn inv_sub_bytes(state: &mut [[u8; 4]; 4]) {
    for row in state.iter_mut() {
        for byte in row.iter_mut() {
            *byte = INVERSE_AES_SBOX[*byte as usize];
        }
    }
}

// ShiftRows
pub fn shift_rows(state: &mut [[u8; 4]; 4]) {
    // 第二行一个字节
    state[1].rotate_left(1);
    // 第三行两个字节
    state[2].rotate_left(2);
    // 第四行三个字节
    state[3].rotate_left(3);
}

pub fn inv_shift_rows(state: &mut [[u8; 4]; 4]) {
    // 第二行一个字节
    state[1].rotate_right(1);
    // 第三行两个字节
    state[2].rotate_right(2);
    // 第四行三个字节
    state[3].rotate_right(3);
}

// GF(2^8) 乘法
fn mul_by_2(x: u8) -> u8 {
    (x << 1) ^ (if x & 0x80 != 0 { 0x1b } else { 0x00 })
}

fn mul_by_3(x: u8) -> u8 {
    mul_by_2(x) ^ x
}

fn mul_by_9(x: u8) -> u8 {
    mul_by_2(mul_by_2(mul_by_2(x))) ^ x
}

fn mul_by_11(x: u8) -> u8 {
    mul_by_2(mul_by_2(mul_by_2(x))) ^ mul_by_2(x) ^ x
}

fn mul_by_13(x: u8) -> u8 {
    mul_by_2(mul_by_2(mul_by_2(x))) ^ mul_by_2(mul_by_2(x)) ^ x
}

fn mul_by_14(x: u8) -> u8 {
    mul_by_2(mul_by_2(mul_by_2(x))) ^ mul_by_2(mul_by_2(x)) ^ mul_by_2(x)
}

// MixColumns
pub fn mix_columns(state: &mut [[u8; 4]; 4]) {
    for col in 0..4 {
        let s0 = state[0][col];
        let s1 = state[1][col];
        let s2 = state[2][col];
        let s3 = state[3][col];

        state[0][col] = mul_by_2(s0) ^ mul_by_3(s1) ^ s2 ^ s3;
        state[1][col] = s0 ^ mul_by_2(s1) ^ mul_by_3(s2) ^ s3;
        state[2][col] = s0 ^ s1 ^ mul_by_2(s2) ^ mul_by_3(s3);
        state[3][col] = mul_by_3(s0) ^ s1 ^ s2 ^ mul_by_2(s3);
    }
}
pub fn inv_mix_columns(state: &mut [[u8; 4]; 4]) {
    for col in 0..4 {
        let s0 = state[0][col];
        let s1 = state[1][col];
        let s2 = state[2][col];
        let s3 = state[3][col];

        state[0][col] = mul_by_14(s0) ^ mul_by_11(s1) ^ mul_by_13(s2) ^ mul_by_9(s3);
        state[1][col] = mul_by_9(s0) ^ mul_by_14(s1) ^ mul_by_11(s2) ^ mul_by_13(s3);
        state[2][col] = mul_by_13(s0) ^ mul_by_9(s1) ^ mul_by_14(s2) ^ mul_by_11(s3);
        state[3][col] = mul_by_11(s0) ^ mul_by_13(s1) ^ mul_by_9(s2) ^ mul_by_14(s3);
    }
}

// AddRoundKey
pub fn add_round_key(state: &mut [[u8; 4]; 4], round_key: &[[u8; 4]; 4]) {
    for i in 0..4 {
        for j in 0..4 {
            state[i][j] ^= round_key[i][j];
        }
    }
}

