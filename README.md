# DNS Server in Rust

This repository contains the code for a **DNS server implemented in Rust**, as part of the tutorial [**Building a DNS Server in Rust**](https://rust-trends.com/posts/building-a-dns-server-in-rust/)  . The tutorial covers:
 - Understanding DNS requests and responses.
 - Handling UDP packets in Rust.
 - Parsing and constructing DNS packets.
 - Implementing decompression of DNS packets.
 - Forwarding DNS queries to resolvers.

## 📖 Tutorial
For a step-by-step guide, check out the full tutorial:
[Building a DNS Server in Rust: Part 1 of 2](https://rust-trends.com/posts/building-a-dns-server-in-rust/)

## 🛠 Installation

Ensure you have **Rust** installed:
```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

## Clone this repository:

```sh
git clone https://github.com/Rust-Trends/dns-server-tutorial.git
cd dns-server-tutorial
```

## 🚀 Running the Server

Goto to the step you want to explore, e.g. step1, and start the DNS server on port 1053:

```sh
cd step1
cargo run
```

## 🔍 Testing with dig

To test your server, open another terminal and run:

```sh
dig @localhost -p 1053 www.rust-trends.com
```

## 🤝 Contributions

Feel free to open issues or submit pull requests to improve the project!

📜 License: MIT
