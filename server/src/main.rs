use base64::{engine::general_purpose, Engine as _};
use exp1::dh_key_pair::DHKeyPair;
use exp1::ecb::aes_ecb_encrypt;
use std::io::{Read, Write};
use std::net::TcpStream;

fn run_client(file_path: &str) -> std::io::Result<()> {
    let mut stream: TcpStream = TcpStream::connect("127.0.0.1:8080")?;

    // 客户端密钥
    let client_keys = DHKeyPair::new();
    // 发送公钥
    stream.write_all(&client_keys.public_key().to_bytes_be())?;

    // 接受公钥
    let mut b_buf = [0u8; 256];
    stream.read_exact(&mut b_buf)?;

    let aes_key = client_keys.calculate_shared_secret_key_with_bytes(&b_buf);

    let mut file_in = std::fs::File::open(file_path)?;

    // let mut chunk = [0u8; 4096];
    let mut encrypted_buf: Vec<u8> = Vec::new();
    // 读取文件
    file_in.read_to_end(&mut encrypted_buf)?;
    // 加密文件
    let encrypted_data = aes_ecb_encrypt(&encrypted_buf, &aes_key);

    // 发送
    stream.write_all(&encrypted_data)?;

    // 写密文
    let mut decrypted_file = std::fs::File::create("./decrypted")?;
    let decrypted_str = general_purpose::STANDARD.encode(&encrypted_data);
    decrypted_file.write_all(&decrypted_str.as_bytes())?;

    Ok(())
}

fn main() {
    let mut file_str = String::new();

    std::io::stdin()
        .read_line(&mut file_str)
        .expect("读取输入失败");
    run_client(file_str.trim());
}
