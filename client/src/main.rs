use exp1::{dh_key_pair::DHKeyPair, ecb::aes_ecb_decrypt};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

fn handle_client(mut stream: TcpStream) -> std::io::Result<()> {
    // 接收公钥
    println!("connection+1\n");
    let mut a_buf = [0u8; 256];
    stream.read_exact(&mut a_buf)?;

    // 生成自己的公钥私钥
    let server_keys = DHKeyPair::new();
    // 发送
    stream.write_all(&server_keys.public_key().to_bytes_be())?;

    // 生成密钥
    let aes_key = server_keys.calculate_shared_secret_key_with_bytes(&a_buf);

    println!("请输入你要保存的文件名: ");
    let mut file_name = String::new();
    std::io::stdin()
        .read_line(&mut file_name)
        .expect("读取输入失败");

    let mut file_out = std::fs::File::create(file_name.trim())?;
    let mut decrypted_buf: Vec<u8> = Vec::new();
    stream.read_to_end(&mut decrypted_buf)?;
    let decrypted_data = aes_ecb_decrypt(&decrypted_buf, &aes_key);
    file_out.write_all(&decrypted_data)?;

    Ok(())
}

fn run_server() -> std::io::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:8080")?;
    println!("Server Listening on 127.0.0.1:8080");
    for client in listener.incoming() {
        match client {
            Ok(stream) => {
                std::thread::spawn(move || {
                    let _ = handle_client(stream);
                });
            }
            Err(e) => eprintln!("Failed to accept client: {}", e),
        }
    }
    Ok(())
}

fn main() {
    run_server();
}
