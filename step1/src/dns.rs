// src/dns.rs
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ErrorCondition {
    #[error("Serialization Error: {0}")]
    SerializationErr(String),

    #[error("Deserialization Error: {0}")]
    DeserializationErr(String),
}

#[derive(Debug)]
pub struct Header {
    pub id: u16,      // identifier
    pub qr: bool,     // 0 for query, 1 for response
    pub opcode: u8,   // 0 for standard query
    pub aa: bool,     // authoritative answer
    pub tc: bool,     // truncated message
    pub rd: bool,     // recursion desired
    pub ra: bool,     // recursion available
    pub z: u8,        // reserved for future use
    pub rcode: u8,    // 0 for no error
    pub qdcount: u16, // number of entries in the question section
    pub ancount: u16, // number of resource records in the answer section
    pub nscount: u16, // number of name server resource records in the authority records section
    pub arcount: u16, // number of resource records in the additional records section
}

impl Header {
    const DNS_HEADER_LEN: usize = 12;

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Header::DNS_HEADER_LEN);

        buf.extend_from_slice(&self.id.to_be_bytes());
        buf.push(
            (self.qr as u8) << 7
                | self.opcode << 3
                | (self.aa as u8) << 2
                | (self.tc as u8) << 1
                | self.rd as u8,
        );
        buf.push((self.ra as u8) << 7 | self.z << 4 | self.rcode);
        buf.extend_from_slice(&self.qdcount.to_be_bytes());
        buf.extend_from_slice(&self.ancount.to_be_bytes());
        buf.extend_from_slice(&self.nscount.to_be_bytes());
        buf.extend_from_slice(&self.arcount.to_be_bytes());

        buf
    }

    pub fn from_bytes(buf: &[u8]) -> Result<Header, ErrorCondition> {
        if buf.len() < Header::DNS_HEADER_LEN {
            return Err(ErrorCondition::DeserializationErr(
                "Buffer length is less than header length".to_string(),
            ));
        }

        Ok(Header {
            id: u16::from_be_bytes([buf[0], buf[1]]),
            qr: (buf[2] & 0b1000_0000) != 0,
            opcode: (buf[2] & 0b0111_1000) >> 3,
            aa: (buf[2] & 0b0000_0100) != 0,
            tc: (buf[2] & 0b0000_0010) != 0,
            rd: (buf[2] & 0b0000_0001) != 0,
            ra: (buf[3] & 0b1000_0000) != 0,
            z: (buf[3] & 0b0111_1000) >> 4,
            rcode: buf[3] & 0b0000_1111,
            qdcount: u16::from_be_bytes([buf[4], buf[5]]),
            ancount: u16::from_be_bytes([buf[6], buf[7]]),
            nscount: u16::from_be_bytes([buf[8], buf[9]]),
            arcount: u16::from_be_bytes([buf[10], buf[11]]),
        })
    }
}
