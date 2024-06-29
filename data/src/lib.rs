mod server_list;

/** Domain suffix to WHOIS server mapping.
 *
 * Keys are domain name suffixes; values are `Some(server_name)` if there is a
 * working server, `None` otherwise.
 *
 * Built from whois(1) by Marco d'Itri and modified; notably, tags and Web
 * WHOIS URLs are discarded. see code of the private `build-data` crate for
 * details.
 */
pub use server_list::SUFFIX_SERVER_LIST;
