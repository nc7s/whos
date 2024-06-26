/*! WHOIS data parsing for domain names.
 */

use {
	crate::SUFFIX_SERVER_LIST,
	lazy_regex::{regex_captures, regex_is_match},
};

#[derive(Debug, Default)]
pub struct Domain {
	pub name: String,
	pub suffix: String,

	pub created: Option<String>,
	pub expiry: Option<String>,

	pub name_servers: Vec<String>,
}

/** Parse WHOIS response for a domain name into [`Domain`].
 *
 * Return None if a response is considered to indicate nonexistence of domain.
 * Sometimes false negative if parsing logic mistakes.
 */
pub fn parse(raw: &str) -> Option<Domain> {
	if not_found(raw) {
		return None;
	}

	let raw = raw.replace("\r\n", "\n").replace(":\n", ":");

	let name = parse_name(&raw)?;
	let suffix = name.rsplit('.').next()?;
	let puny_name = if suffix.chars().next()?.is_ascii_alphabetic() {
		name.clone()
	} else {
		let puny = punycode::encode(suffix).ok()?;
		name.replace(suffix, &format!("xn--{puny}"))
	};

	let suffix = SUFFIX_SERVER_LIST
		.keys()
		.find(|&suffix| puny_name.ends_with(suffix))?
		.to_string();

	if suffix == ".de" {
		return if raw.contains(": connect") { Some(Domain { name, suffix, ..Default::default() }) } else { None };
	}

	let created = parse_created(&raw);
	let expiry = parse_expiry(&raw);
	let name_servers = parse_ns(&raw);
	Some(Domain { name, suffix, created, expiry, name_servers })
}

fn not_found(raw: &str) -> bool {
	/* `returned 0 objects` is largely IANA */
	regex_is_match!(r"([Nn]o \w+ [Ff]ound|returned 0 objects|NOT FOUND)", raw)
}

/** Find and parse the domain name.
 */
pub fn parse_name(raw: &str) -> Option<String> {
	regex_captures!(
		r"^.*(?:[Dd]omain:?\s*[Nn]ame\s*[:.\]]*|[Dd]omain\s*:?|DOMAIN\s+NAME:|[Dd]omain\.+:|Nom de domaine:|NOMBRE DE DOMINIO:|Informations about)\W*([\w.-]+\.(?:[Xx][Nn]--[\w-]+|\w+))"m,
		raw
	)
	.map(|caps| caps.1)
	.map(|s| s.to_ascii_lowercase())
}

/** Find and parse the created time.
 *
 * **Note**: this is still the raw result. Turning into datetime structs is not
 * implemented.
*/
pub fn parse_created(raw: &str) -> Option<String> {
	/* Notes:
	 * - `^`: start of line (.ac.uk series' newlines are normalized)
	 * - `[(]?`: .xn--zfr164b has `注册时间(Creation Date): ...`
	 * - various keywords
	 * - `\W*`: separator between keyword and value, basically `[:. ]`, or none
	 * - matches either RFC3339/ISO8601 timestamps, dd.mm.yyyy, or some obscure
	 * textual description
	 */
	regex_captures!(r"^.*[(]?(?:(?:[Cc]reat(?:ion|ed)|[Rr]egist(?:ered|ration))\s*(?:[Dd]ate|[Oo]n|[Tt]ime)?|dateregistered|[Aa]ctivation|Fecha de activación|activated|création)\W*(\d[0-9TZ.:-]+|\w+\s+\w*\d+\w+)"m, raw)
		.map(|caps| caps.1)
		.map(|s| s.to_string())
}

/** Find and parse the expiry time.
 *
 * **Note**: this is still the raw result. Turning into datetime structs is not
 * implemented.
*/
pub fn parse_expiry(raw: &str) -> Option<String> {
	/* Basically the same as parse_created, except keywords */
	regex_captures!(r"^.*(?:[Ee]xpir(?:y|ation|es?)\s*(?:[Dd]ate|[Tt]ime|[Oo]n|)|[Ee]xp [Dd]ate|[Rr]enewal [Dd]ate|datebilleduntil|paid-till|[Vv]alidity:|[Vv]alid [Uu]ntil|Fecha de corte)\W*([0-9A-Za-z:. -]+\d[0-9A-Za-z:. -]+)"m, raw)
		.map(|caps| caps.1)
		.map(|s| s.to_string())
}

/** Find and parse the name servers. */
pub fn parse_ns(raw: &str) -> Vec<String> {
	raw.lines()
		.filter_map(|line| {
			regex_captures!(r"(?:[Nn]servers?|[Nn]ame\s*[Ss]ervers?|DNS:)\W+([0-9a-zA-Z.-]+)", line)
				.map(|caps| caps.1)
				.map(|s| s.to_ascii_lowercase())
		})
		.collect()
}
