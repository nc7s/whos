use std::io::{Read, Write};

pub fn whois_raw(name: &str, server: (&str, u16)) -> std::io::Result<String> {
	let mut stream = std::net::TcpStream::connect(server)?;
	stream.write_all(name.as_bytes())?;
	stream.write_all(b"\r\n")?;
	let mut buf = String::new();
	stream.read_to_string(&mut buf)?;
	Ok(buf)
}
