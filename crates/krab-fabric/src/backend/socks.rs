//! SOCKS5-dialed TCP backend, for Tor (RFC 4).
//!
//! Contact and sync endpoints are separated, and the onion key is never
//! derived from the node identity: it is a separate key, and the address
//! appears only inside the private credential.
