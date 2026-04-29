// src/main.rs
use std::net::UdpSocket;
use std::time::Duration;

mod dns;
use dns::{Header, ResourceRecord};

fn forward_query(query: &[u8]) -> Result<Vec<u8>, String> {
    let resolver = "8.8.8.8:53";
    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| e.to_string())?;
    socket.send_to(query, resolver).map_err(|e| e.to_string())?;
    let mut buf = [0; 512];
    let (len, _) = socket.recv_from(&mut buf).map_err(|e| e.to_string())?;
    Ok(buf[..len].to_vec())
}

fn main() {
    let socket = UdpSocket::bind("0.0.0.0:1053").expect("Could not bind to port 1053");
    let mut buf = [0; 512];

    println!("DNS server is running at port 1053");
    println!("Forwarding queries to 8.8.8.8");

    loop {
        let (len, addr) = match socket.recv_from(&mut buf) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("Failed to receive: {}", e);
                continue;
            }
        };

        let query = &buf[..len];

        if let Ok(header) = Header::from_bytes(query) {
            println!(
                "\nQuery from {} (ID: {:#06x}, questions: {})",
                addr, header.id, header.qdcount
            );
        }

        match forward_query(query) {
            Ok(response) => {
                if let Ok(resp_header) = Header::from_bytes(&response) {
                    println!(
                        "Response: {} answer(s), rcode={}",
                        resp_header.ancount, resp_header.rcode
                    );

                    // Skip header and question section to reach the answer section
                    let mut offset = 12;
                    for _ in 0..resp_header.qdcount {
                        while offset < response.len() {
                            let byte = response[offset];
                            if byte == 0 {
                                offset += 1;
                                break;
                            } else if byte & 0b11000000 == 0b11000000 {
                                offset += 2;
                                break;
                            } else {
                                offset += 1 + byte as usize;
                            }
                        }
                        offset += 4; // skip QTYPE + QCLASS
                    }

                    for i in 0..resp_header.ancount {
                        match ResourceRecord::from_bytes(&response, offset) {
                            Ok((record, next_offset)) => {
                                println!(
                                    "  Answer {}: {} -> {:?}",
                                    i + 1,
                                    record.name,
                                    record.rdata
                                );
                                offset = next_offset;
                            }
                            Err(e) => {
                                eprintln!("  Failed to parse answer {}: {}", i + 1, e);
                                break;
                            }
                        }
                    }
                }

                if let Err(e) = socket.send_to(&response, addr) {
                    eprintln!("Failed to send response to {}: {}", addr, e);
                }
            }
            Err(e) => eprintln!("Forward failed: {}", e),
        }
    }
}
