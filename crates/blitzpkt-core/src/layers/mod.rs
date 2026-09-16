//! Protocol layer definitions.
//!
//! Every module here follows the same shape: a `FIELDS` table written from the
//! relevant RFC, a `header_len` function, a `next` function, and a `DESC`
//! binding them together. Adding a protocol means adding a module and one arm
//! in `proto::desc`.
//!
//! Provenance: field layouts come from the RFC cited at the top of each module.
//! See CONTRIBUTING.md before editing.

pub mod arp;
pub mod bootp;
pub mod dns;
pub mod dot1q;
pub mod ether;
pub mod icmp;
pub mod icmpv6;
pub mod ipv4;
pub mod ipv6;
pub mod raw;
pub mod tcp;
pub mod udp;
