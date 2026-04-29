// src/main.rs
use std::net::UdpSocket;

mod dns;
use dns::{Class, Header, Label, Question, ResourceRecord, Type};

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
        let data = buf[..len].to_vec();

        println!("\nReceived query from {} with length {} bytes", addr, len);
        println!("\n### DNS Query: ###");
        debug_print_bytes(&data);

        let header = Header::from_bytes(&data[..12]).expect("Could not parse DNS header");
        println!("\n{:?}", header);

        // Parse all questions using decompress_name to correctly handle compressed domain names
        let mut questions: Vec<Question> = Vec::new();
        let mut offset = 12;

        for _ in 0..header.qdcount {
            match Question::decompress_name(&data, offset) {
                Ok((name, next_offset)) => {
                    let qtype = Type::from_bytes(&data[next_offset..next_offset + 2])
                        .expect("Could not parse QTYPE");
                    let qclass = Class::from_bytes(&data[next_offset + 2..next_offset + 4])
                        .expect("Could not parse QCLASS");
                    offset = next_offset + 4;

                    println!("Question: {} ({:?}, {:?})", name, qtype, qclass);

                    let labels = name
                        .split('.')
                        .map(|l| Label::new(l.as_bytes()).expect("Invalid label"))
                        .collect();

                    questions.push(Question {
                        name: labels,
                        qtype,
                        qclass,
                    });
                }
                Err(e) => eprintln!("Decompression error: {}", e),
            }
        }

        // Build one hardcoded answer per question
        let answers: Vec<ResourceRecord> = questions
            .iter()
            .map(|q| {
                let name = q.name.iter().map(|l| l.as_str()).collect::<Vec<_>>().join(".");
                ResourceRecord {
                    name,
                    rtype: q.qtype.clone(),
                    rclass: q.qclass.clone(),
                    ttl: 60,
                    rdlength: 4,
                    rdata: vec![172, 67, 221, 148],
                }
            })
            .collect();

        let response_header = Header {
            id: header.id,
            qr: true,
            opcode: header.opcode,
            aa: false,
            tc: false,
            rd: header.rd,
            ra: false,
            z: 0,
            rcode: if header.opcode == 0 { 0 } else { 4 },
            qdcount: questions.len() as u16,
            ancount: answers.len() as u16,
            nscount: 0,
            arcount: 0,
        };

        let mut response: Vec<u8> = Vec::new();
        response.extend_from_slice(&response_header.to_bytes());
        for q in &questions {
            response.extend_from_slice(&q.to_bytes());
        }
        for a in &answers {
            response.extend_from_slice(&a.to_bytes());
        }

        println!("\n### Response: ###");
        debug_print_bytes(&response);

        socket
            .send_to(&response, addr)
            .expect("Could not send response");
    }
}
