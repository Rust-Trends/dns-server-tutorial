// src/dns.rs
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ErrorCondition {
    #[error("Serialization Error: {0}")]
    SerializationErr(String),

    #[error("Deserialization Error: {0}")]
    DeserializationErr(String),

    #[error("Invalid Label")]
    InvalidLabel,
}

/// Maximum DNS message size without EDNS0
const MAX_DNS_MESSAGE_SIZE: usize = 512;

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

    // Serialize the header to a byte array
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

    // Deserialize the header from a byte array
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
            z: (buf[3] & 0b0111_0000) >> 4,
            rcode: buf[3] & 0b0000_1111,
            qdcount: u16::from_be_bytes([buf[4], buf[5]]),
            ancount: u16::from_be_bytes([buf[6], buf[7]]),
            nscount: u16::from_be_bytes([buf[8], buf[9]]),
            arcount: u16::from_be_bytes([buf[10], buf[11]]),
        })
    }
}

#[derive(Debug, Clone)]
pub struct Question {
    pub name: Vec<Label>,
    pub qtype: Type,
    pub qclass: Class,
}

#[derive(Debug, Clone)]
pub struct Label(String);

impl Label {
    pub fn new(label: &[u8]) -> Result<Self, ErrorCondition> {
        match std::str::from_utf8(label) {
            Ok(s) => Ok(Label(s.to_string())),
            Err(_) => Err(ErrorCondition::InvalidLabel),
        }
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone)]
pub enum Type {
    // Below are Resource Record Types and QTYPES
    A = 1,      // a host address
    NS = 2,     // an authoritative name server
    MD = 3,     // a mail destination (Obsolete - use MX)
    MF = 4,     // a mail forwarder (Obsolete - use MX)
    CNAME = 5,  // the canonical name for an alias
    SOA = 6,    // marks the start of a zone of authority
    MB = 7,     // a mailbox domain name (EXPERIMENTAL)
    MG = 8,     // a mail group member (EXPERIMENTAL)
    MR = 9,     // a mail rename domain name (EXPERIMENTAL)
    NULL = 10,  // a null RR (EXPERIMENTAL)
    WKS = 11,   // a well known service description
    PTR = 12,   // a domain name pointer
    HINFO = 13, // host information
    MINFO = 14, // mailbox or mail list information
    MX = 15,    // mail exchange
    TXT = 16,   // text strings

    // Below are only QTYPES
    AXFR = 252,  // A request for a transfer of an entire zone
    MAILB = 253, // A request for mailbox-related records (MB, MG or MR)
    MAILA = 254, // A request for mail agent RRs (Obsolete - see MX)
    _ALL_ = 255, // A request for all records
}

#[derive(Debug, Clone)]
pub enum Class {
    // Below are Resource Record Classes and QCLASS
    IN = 1, // the Internet
    CS = 2, // the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
    CH = 3, // the CHAOS class
    HS = 4, // Hesiod [Dyer 87]

    // Below are only QCLASSES
    _ALL_ = 255,
}

impl std::fmt::Display for Type {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let msg: &str = match self {
            Type::A => "a host address",
            Type::NS => "an authoritative name server",
            Type::MD => "a mail destination (Obsolete - use MX)",
            Type::MF => "a mail forwarder (Obsolete - use MX)",
            Type::CNAME => "the canonical name for an alias",
            Type::SOA => "marks the start of a zone of authority",
            Type::MB => "a mailbox domain name (EXPERIMENTAL)",
            Type::MG => "a mail group member (EXPERIMENTAL)",
            Type::MR => "a mail rename domain name (EXPERIMENTAL)",
            Type::NULL => "a null RR (EXPERIMENTAL)",
            Type::WKS => "a well known service description",
            Type::PTR => "a domain name pointer",
            Type::HINFO => "host information",
            Type::MINFO => "mailbox or mail list information",
            Type::MX => "mail exchange",
            Type::TXT => "text strings",
            Type::AXFR => "A request for a transfer of an entire zone",
            Type::MAILB => "A request for mailbox-related records (MB, MG or MR)",
            Type::MAILA => "A request for mail agent RRs (Obsolete - see MX)",
            Type::_ALL_ => "A request for all records",
        };

        write!(f, "{}", msg)
    }
}

impl Type {
    pub fn from_bytes(bytes: &[u8]) -> Result<Type, ErrorCondition> {
        match u16::from_be_bytes([bytes[0], bytes[1]]) {
            1 => Ok(Type::A),
            2 => Ok(Type::NS),
            3 => Ok(Type::MD),
            4 => Ok(Type::MF),
            5 => Ok(Type::CNAME),
            6 => Ok(Type::SOA),
            7 => Ok(Type::MB),
            8 => Ok(Type::MG),
            9 => Ok(Type::MR),
            10 => Ok(Type::NULL),
            11 => Ok(Type::WKS),
            12 => Ok(Type::PTR),
            13 => Ok(Type::HINFO),
            14 => Ok(Type::MINFO),
            15 => Ok(Type::MX),
            16 => Ok(Type::TXT),
            252 => Ok(Type::AXFR),
            253 => Ok(Type::MAILB),
            254 => Ok(Type::MAILA),
            255 => Ok(Type::_ALL_),
            n => Err(ErrorCondition::DeserializationErr(
                format!("Unknown Question Type {}", n).to_string(),
            )),
        }
    }

    pub fn to_bytes(&self) -> [u8; 2] {
        let num = match self {
            Type::A => 1,
            Type::NS => 2,
            Type::MD => 3,
            Type::MF => 4,
            Type::CNAME => 5,
            Type::SOA => 6,
            Type::MB => 7,
            Type::MG => 8,
            Type::MR => 9,
            Type::NULL => 10,
            Type::WKS => 11,
            Type::PTR => 12,
            Type::HINFO => 13,
            Type::MINFO => 14,
            Type::MX => 15,
            Type::TXT => 16,
            Type::AXFR => 252,
            Type::MAILB => 253,
            Type::MAILA => 254,
            Type::_ALL_ => 255,
        };

        u16::to_be_bytes(num)
    }
}

impl Class {
    pub fn from_bytes(buf: &[u8]) -> Result<Self, ErrorCondition> {
        let num = u16::from_be_bytes([buf[0], buf[1]]);
        match num {
            1 => Ok(Class::IN),
            2 => Ok(Class::CS),
            3 => Ok(Class::CH),
            4 => Ok(Class::HS),
            _ => Err(ErrorCondition::DeserializationErr(
                format!("Unknown Question Class {}", num).to_string(),
            )),
        }
    }

    pub fn to_bytes(&self) -> [u8; 2] {
        let num = match self {
            Class::IN => 1,
            Class::CS => 2,
            Class::CH => 3,
            Class::HS => 4,
            Class::_ALL_ => 255,
        };

        u16::to_be_bytes(num)
    }
}

impl Question {
    // The from_bytes() function reconstructs a Question struct by iterating through the buffer, extracting labels,
    // parsing the query type and class.
    pub fn from_bytes(buf: &[u8]) -> Result<Self, ErrorCondition> {
        let mut index = 0;
        let mut labels: Vec<Label> = Vec::new();

        println!("Labels:");
        while buf[index] != 0 {
            let len = buf[index] as usize;
            index += 1;
            labels.push(Label::new(&buf[index..index + len])?);
            println!("{:?}", labels); // For debugging purposes
            index += len;
        }

        index += 1;

        let qtype = Type::from_bytes(&buf[index..index + 2])?;
        index += 2;
        let qclass = Class::from_bytes(&buf[index..index + 2])?;

        Ok(Question {
            name: labels,
            qtype,
            qclass,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // Write the labels to the buffer and add . inbetween and end with 0
        for label in &self.name {
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.0.as_bytes());
        }
        buf.push(0);

        // Write the question type and class to the buffer
        buf.extend_from_slice(&self.qtype.to_bytes());
        buf.extend_from_slice(&self.qclass.to_bytes());

        buf
    }

    pub fn decompress_name(buf: &[u8], start: usize) -> Result<(String, usize), ErrorCondition> {
        let mut name = String::new();
        let mut index = start;
        let mut jumped = false;
        let mut jump_position = 0;

        loop {
            let len = buf[index] as usize;
            if len == 0 {
                index += 1;
                break;
            }

            if len & 0b11000000 == 0b11000000 {
                if !jumped {
                    jump_position = index + 2;
                }
                let offset = ((len & 0b00111111) as usize) << 8 | buf[index + 1] as usize;
                index = offset;
                jumped = true;
                continue;
            }

            index += 1;
            if !name.is_empty() {
                name.push('.');
            }
            name.push_str(&String::from_utf8_lossy(&buf[index..index + len]));
            index += len;
        }

        if !jumped {
            jump_position = index;
        }

        Ok((name, jump_position))
    }
}

#[derive(Debug, Clone)]
pub struct ResourceRecord {
    pub name: String,
    pub rtype: Type,
    pub rclass: Class,
    pub ttl: u32,
    pub rdlength: u16,
    pub rdata: Vec<u8>,
}

impl Default for ResourceRecord {
    fn default() -> Self {
        ResourceRecord {
            name: String::from("www.rust-trends.com"),
            rtype: Type::A,
            rclass: Class::IN,
            ttl: 60,
            rdlength: 4,
            rdata: Vec::from([172, 67, 221, 148]),
        }
    }
}

impl ResourceRecord {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(MAX_DNS_MESSAGE_SIZE);

        self.name.split('.').for_each(|label| {
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        });

        buf.push(0);
        buf.extend_from_slice(&self.rtype.to_bytes());
        buf.extend_from_slice(&self.rclass.to_bytes());
        buf.extend_from_slice(&self.ttl.to_be_bytes());
        buf.extend_from_slice(&self.rdlength.to_be_bytes());
        buf.extend_from_slice(&self.rdata);

        buf
    }

    pub fn from_bytes(buf: &[u8], offset: usize) -> Result<(Self, usize), ErrorCondition> {
        let (name, mut index) = Question::decompress_name(buf, offset)?;

        let rtype = Type::from_bytes(&buf[index..index + 2])?;
        index += 2;
        let rclass = Class::from_bytes(&buf[index..index + 2])?;
        index += 2;
        let ttl = u32::from_be_bytes(buf[index..index + 4].try_into().unwrap());
        index += 4;
        let rdlength = u16::from_be_bytes(buf[index..index + 2].try_into().unwrap()) as usize;
        index += 2;
        let rdata = buf[index..index + rdlength].to_vec();
        index += rdlength;

        Ok((
            ResourceRecord {
                name,
                rtype,
                rclass,
                ttl,
                rdlength: rdlength as u16,
                rdata,
            },
            index,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decompress_name_with_pointer() {
        // Two-question packet: first has uncompressed www.rust-trends.com,
        // second has dev.rust-trends.com using a pointer to offset 0x10
        let packet: Vec<u8> = vec![
            // Header (12 bytes)
            0x43, 0xE6, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // Question 1 name: www.rust-trends.com (starts at offset 12)
            0x03, b'w', b'w', b'w',
            0x0B, b'r', b'u', b's', b't', b'-', b't', b'r', b'e', b'n', b'd', b's',
            0x03, b'c', b'o', b'm', 0x00,
            // Question 1 type + class
            0x00, 0x01, 0x00, 0x01,
            // Question 2 name: dev + pointer to offset 0x10 (starts at offset 37)
            0x03, b'd', b'e', b'v',
            0xC0, 0x10,
            // Question 2 type + class
            0x00, 0x01, 0x00, 0x01,
        ];

        let (name1, next1) = Question::decompress_name(&packet, 12).unwrap();
        assert_eq!(name1, "www.rust-trends.com");
        assert_eq!(next1, 33);

        let (name2, next2) = Question::decompress_name(&packet, 37).unwrap();
        assert_eq!(name2, "dev.rust-trends.com");
        assert_eq!(next2, 43);
    }
}
