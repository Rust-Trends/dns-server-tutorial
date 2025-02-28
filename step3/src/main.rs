// src/main.rs
use std::net::UdpSocket;

mod dns;
use dns::{Header, Question, ResourceRecord};

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

        // We parsed the DNS query and question, now we can respond to it
        let answer = ResourceRecord::default();

        println!("{:?}", answer);

        let response_header = Header {
            id: header.id,
            qr: true,              // It is a query response
            opcode: header.opcode, // Standard query
            aa: false,             // Not authoritative
            tc: false,             // Not truncated
            rd: header.rd,         // Recursion desired
            ra: false,             // Recursion not available
            z: 0,                  // Reserved
            rcode: if header.opcode == 0 { 0 } else { 4 },
            qdcount: 1, // Question count we assume is 1
            ancount: 1, // Answer count is 1
            nscount: 0, // Name server count is 0
            arcount: 0, // Additional record count is 0
        };

        // Create a response message with the header and question
        let mut response: Vec<u8> = Vec::new();
        response.extend_from_slice(&response_header.to_bytes());
        response.extend_from_slice(&question.to_bytes());
        response.extend_from_slice(&answer.to_bytes());

        // Send the response back to the client
        socket
            .send_to(&response, addr)
            .expect("Could not send response");
    }
}
