use std::fs;

fn main() {
	build_suffix_server_list();
}

fn build_suffix_server_list() {
	const ERR_MDWHOIS: &str = "make sure git submodule md-whois is updated";

	let normal_raw = fs::read_to_string("md-whois/tld_serv_list")
		.expect(ERR_MDWHOIS)
		.replace("NONE", "")
		/* Probably has use in the original but not for us */
		.replace("VERISIGN", "")
		/* This doesn't seem to affect the query */
		.replace("RECURSIVE", "")
		/* .in-addr.arpa, PTR records, special cased */
		.replace("ARPA", "")
		/* .ip6.arpa, same */
		.replace("IP6", "");
	let normal: Vec<(&str, Option<&str>)> = normal_raw
		.lines()
		.filter(|line| !line.is_empty() && !line.starts_with('#'))
		.map(|line| line.split('#').next().unwrap().trim())
		.map(|line| {
			let split = line.splitn(2, &[' ', '\t']).collect::<Vec<&str>>();
			let server = split.get(1).map(|value| value.trim());
			let server = if server.map(|value| value.starts_with("WEB")) == Some(true) { None } else { server };
			(split[0], server)
		})
		.collect();

	let ntlds_raw = fs::read_to_string("md-whois/new_gtlds_list").expect(ERR_MDWHOIS);
	let ntlds: Vec<&str> = ntlds_raw
		.lines()
		.filter(|line| !line.is_empty() && !line.starts_with('#'))
		.collect();

	let mut lines = Vec::new();
	const OPEN: &str = "pub static SUFFIX_SERVER_LIST: phf::OrderedMap<&str, Option<&str>> = phf::phf_ordered_map!(";
	lines.push(OPEN.to_string());

	for (suffix, value) in normal {
		match value {
			Some(value) => lines.push(format!("\t\"{suffix}\" => Some(\"{value}\"),")),
			None => lines.push(format!("\t\"{suffix}\" => None,")),
		}
	}

	lines.push("\t/* start nTLDs */".to_string());
	for tld in ntlds {
		lines.push(format!("\t\".{tld}\" => Some(\"whois.nic.{tld}\"),"));
	}

	lines.push(");".to_string());

	fs::write("data/src/server_list.rs", lines.join("\n")).unwrap();
}
