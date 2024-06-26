/*! # `whos("th.at")?` - Rust whois library

Query data using the WHOIS protocol (RFC 3912).

```rust
let domain = whos::domain("debian.org").unwrap().unwrap();
assert_eq!(domain.name, "debian.org");
assert_eq!(domain.suffix, ".org");
assert_eq!(domain.created.as_deref(), Some("1999-03-10T05:00:00Z"));
```
Parsing is currently focused on domain names.
 */

pub mod domain;
mod raw;
mod server_list;
pub use raw::whois_raw;
/** Suffix-to-server mappings generated from data files from whois(1).
 *
 * Keys are domain name suffixes; values are `Some(server_name)` if there is a
 * working server, `None` otherwise.
 */
pub use server_list::SUFFIX_SERVER_LIST;

#[derive(Debug, thiserror::Error)]
pub enum Error {
	#[error("no whois server available")]
	NoServer,
	#[error("unknown domain suffix")]
	UnknownSuffix,
	#[error("io error")]
	Io(#[from] std::io::Error),
}

/** Query WHOIS data for domain `name`.
 * Data from whois(1) is used to determine which server to query.
 */
pub fn domain(name: &str) -> Result<Option<domain::Domain>, Error> {
	for (suffix, maybe_server) in SUFFIX_SERVER_LIST.entries() {
		if name.ends_with(suffix) {
			return if let Some(server) = maybe_server {
				let raw = whois_raw(name, (server, 43))?;
				Ok(domain::parse(&raw))
			} else {
				Err(Error::NoServer)
			};
		}
	}
	Err(Error::UnknownSuffix)
}
