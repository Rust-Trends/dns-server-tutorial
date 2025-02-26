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
    pub fn from_bytes(buf: &[u8]) -> Result<Self, ErrorCondition> {
        // Extract the labels from the buffer
        // and add it to the Vec<Label>
        let mut index = 0;
        let mut labels: Vec<Label> = Vec::new();

        println!("Labels:");
        while buf[index] != 0 {
            let len = buf[index] as usize;
            index += 1;
            labels.push(Label::new(&buf[index..index + len])?);
            println!("{:?}", labels);
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
            rdata: Vec::from([172,67,221,148]),
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
}
