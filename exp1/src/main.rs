// S盒和逆S盒的定义
mod aes;
mod block;
mod dh_key_pair;
mod dh_p_g;
mod ecb;
mod key_expansion;
mod table;

// S盒运算和逆S盒运算
use dh_key_pair::DHKeyPair;
use ecb::{aes_ecb_decrypt_string, aes_ecb_encrypt_string};
fn main() {
    // 模拟通信双方协商P,G，生成公钥私钥
    let dh_pair_1 = DHKeyPair::new();
    let dh_pair_2 = DHKeyPair::new();

    // 模拟传输，进行计算生成aes128位的密钥
    let shared_key1 = dh_pair_1.derive_aes_key(&dh_pair_2.public_key());
    let shared_key2 = dh_pair_2.derive_aes_key(&dh_pair_1.public_key());

    // 输入待加密的字符串
    println!("请输入要加密的字符串:");
    let mut plainstring = String::new();

    std::io::stdin()
        .read_line(&mut plainstring)
        .expect("读取输入失败");
    let plainstring = plainstring.trim().to_string();

    // 加密
    let cipherstring = aes_ecb_encrypt_string(&plainstring, &shared_key1);
    println!("加密后的密文:{}", cipherstring);

    // 解密
    let decryptedtext = aes_ecb_decrypt_string(&cipherstring, &shared_key2);
    println!("解密后的明文:{}", decryptedtext);
}
