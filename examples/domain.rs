use {
	std::io::{IsTerminal, Read},
	whos::domain,
};

fn show_usage() {
	eprintln!("Usage: program DOMAIN\nUsage: whois example.com | program");
}

fn main() {
	let mut stdin = std::io::stdin().lock();
	let result;

	if stdin.is_terminal() {
		let Some(name) = std::env::args().nth(1) else {
			return show_usage();
		};
		result = domain(&name).expect("failed to query");
	} else {
		let mut buf = String::new();
		stdin.read_to_string(&mut buf).expect("failed to read stdin");
		buf = buf.trim().to_string();
		if buf.is_empty() {
			return show_usage();
		}
		result = domain::parse(&buf);
	}

	if result.is_none() {
		return println!("no result");
	}

	match result {
		Some(domain) => println!(
			"domain : {}\ncreated: {}\nexpiry : {}\nname servers: {}",
			domain.name,
			domain.created.unwrap_or("unknown".to_string()),
			domain.expiry.unwrap_or("unknown".to_string()),
			domain.name_servers.join(" "),
		),
		None => println!("seems to be unregistered"),
	}
}
