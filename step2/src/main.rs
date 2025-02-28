// src/main.rs
use std::net::UdpSocket;

mod dns;
use dns::{Header, Question};

// Debug print hex bytes of a buffer 16 bytes width followed by the ASCII representation of the bytes
fn debug_print_bytes(buf: &[u8]) {
    for (i, chunk) in buf.chunks(16).enumerate() {
        print!("{:08x}: ", i * 16);
        for byte in chunk {
            print!("{:02x} ", byte);
        }
        for _ in 0..(16 - chunk.len()) {
            print!("   ");
        }
        print!("  ");
        for byte in chunk {
            if *byte >= 32 && *byte <= 126 {
                print!("{}", *byte as char);
            } else {
                print!(".");
            }
        }
        println!();
    }
}

fn main() {
    let socket = UdpSocket::bind("0.0.0.0:1053").expect("Could not bind to port 1053");
    let mut buf = [0; 512];

    println!("DNS server is running at port 1053");

    loop {
        let (len, addr) = socket.recv_from(&mut buf).expect("Could not receive data");

        println!("\nReceived query from {} with length {} bytes", addr, len);
        println!("\n### DNS Query: ###");
        debug_print_bytes(&buf[..len]);

        let header = Header::from_bytes(&buf[..12]).expect("Could not parse DNS header");
        println!("\n{:?}", header);

        println!("\n### Question: ###");
        debug_print_bytes(&buf[12..len]);
        println!();

        let question = Question::from_bytes(&buf[12..len]).expect("Could not parse DNS question");
        println!("\n{:?}", question);
    }
}
