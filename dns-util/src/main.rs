use std::net::UdpSocket;
use std::time::Duration;

// Crafted DNS packet with two questions:
//   1. www.rust-trends.com (uncompressed)
//   2. dev.rust-trends.com (compressed via pointer to offset 0x10)
const DATA: [u8; 47] = [
    // Header: ID=0x43E6, flags=standard query, QDCOUNT=2
    0x43, 0xE6, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // Question 1: www.rust-trends.com, Type A, Class IN
    0x03, 0x77, 0x77, 0x77,                                        // "www"
    0x0B, 0x72, 0x75, 0x73, 0x74, 0x2D, 0x74, 0x72, 0x65, 0x6E, 0x64, 0x73, // "rust-trends"
    0x03, 0x63, 0x6F, 0x6D, 0x00,                                  // "com" + null
    0x00, 0x01, 0x00, 0x01,                                        // Type A, Class IN
    // Question 2: dev + pointer to offset 0x10 (rust-trends.com), Type A, Class IN
    0x03, 0x64, 0x65, 0x76,                                        // "dev"
    0xC0, 0x10,                                                    // pointer to offset 16
    0x00, 0x01, 0x00, 0x01,                                        // Type A, Class IN
];

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
    let socket = UdpSocket::bind("0.0.0.0:0").expect("Failed to bind socket");
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("Failed to set timeout");

    println!("Sending compressed DNS packet to 127.0.0.1:1053...");
    println!("\n### Packet sent: ###");
    debug_print_bytes(&DATA);

    socket
        .send_to(&DATA, "127.0.0.1:1053")
        .expect("Failed to send packet");

    let mut buf = [0; 512];
    match socket.recv_from(&mut buf) {
        Ok((amt, src)) => {
            println!("\nReceived {} bytes from {}:", amt, src);
            println!("\n### Response: ###");
            debug_print_bytes(&buf[..amt]);
        }
        Err(e) => eprintln!("No response (is the server running on port 1053?): {}", e),
    }
}
