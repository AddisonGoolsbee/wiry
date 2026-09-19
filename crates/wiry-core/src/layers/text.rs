//! Shared machinery for the line-oriented application protocols.
//!
//! HTTP (RFC 9112 §2.1), SIP (RFC 3261 §7), FTP (RFC 959 §4), SMTP (RFC 5321
//! §4.1), IMAP (RFC 3501 §2.2) and syslog (RFC 5424 §6) are not field tables at
//! any offset: they are CRLF-delimited text. They are served here as the same
//! named-item list `options.rs` already produces for a TLV region, so the
//! engine keeps two shapes rather than gaining a third — see DEVIATIONS T1.

use crate::options::{Item, ItemValue};

pub fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

pub fn item(name: &str, code: u32, v: &[u8]) -> Item {
    Item {
        name: std::borrow::Cow::Owned(name.to_string()),
        code,
        value: ItemValue::Text(text(v)),
    }
}

pub fn named(name: &'static str, v: &[u8]) -> Item {
    Item::named(name, 0, ItemValue::Text(text(v)))
}

fn trim(mut b: &[u8]) -> &[u8] {
    while let Some((f, rest)) = b.split_first() {
        if f.is_ascii_whitespace() {
            b = rest;
        } else {
            break;
        }
    }
    while let Some((l, rest)) = b.split_last() {
        if l.is_ascii_whitespace() {
            b = rest;
        } else {
            break;
        }
    }
    b
}

/// Lines with their terminators removed. A final unterminated line counts:
/// a snaplen-clipped capture ends mid-message routinely.
pub fn lines(data: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut start = 0usize;
    for (i, c) in data.iter().enumerate() {
        if *c == b'\n' {
            let mut end = i;
            if end > start && data[end - 1] == b'\r' {
                end -= 1;
            }
            out.push(&data[start..end]);
            start = i + 1;
        }
        if out.len() >= 256 {
            return out;
        }
    }
    if start < data.len() {
        out.push(&data[start..]);
    }
    out
}

/// Offset just past the blank line that ends a header block, or the whole
/// input when the block was clipped before it.
pub fn headers_end(data: &[u8]) -> usize {
    header_block(data).unwrap_or(data.len())
}

/// Offset just past the blank line that ends a header block, or `None` when
/// the block was clipped before it. A reassembler needs to tell a clipped
/// block from a complete one; a dissector takes what it has.
pub fn header_block(data: &[u8]) -> Option<usize> {
    let mut i = 0usize;
    while i < data.len() {
        let nl = i + data[i..].iter().position(|c| *c == b'\n')?;
        let line_len = if nl > i && data[nl - 1] == b'\r' {
            nl - 1 - i
        } else {
            nl - i
        };
        if line_len == 0 {
            return Some(nl + 1);
        }
        i = nl + 1;
    }
    None
}

/// `Content-type` and `CONTENT-TYPE` are the same field name (RFC 9110 §5.1),
/// so one spelling is chosen rather than leaving callers to guess.
fn canonical(name: &[u8]) -> String {
    let mut out = String::with_capacity(name.len());
    let mut upper = true;
    for c in name {
        let c = *c as char;
        out.push(if upper {
            c.to_ascii_uppercase()
        } else {
            c.to_ascii_lowercase()
        });
        upper = c == '-';
    }
    out
}

/// Field lines of a header block, obs-fold continuations joined onto the line
/// they continue (RFC 9112 §5.2).
pub fn header_items(block: &[u8]) -> Vec<Item> {
    let mut out: Vec<Item> = Vec::new();
    for line in lines(block) {
        if line.is_empty() {
            break;
        }
        if line[0] == b' ' || line[0] == b'\t' {
            if let Some(last) = out.last_mut() {
                if let ItemValue::Text(t) = &mut last.value {
                    t.push(' ');
                    t.push_str(&text(trim(line)));
                }
            }
            continue;
        }
        match line.iter().position(|c| *c == b':') {
            Some(i) => out.push(item(&canonical(&line[..i]), 0, trim(&line[i + 1..]))),
            None => out.push(named("Unstructured", line)),
        }
    }
    out
}

/// The three space-separated parts of an HTTP or SIP start line. A line with
/// fewer parts is not one, which is what keeps a mid-stream TCP segment from
/// dissecting as a message.
pub fn start_line(line: &[u8]) -> Option<(&[u8], &[u8], &[u8])> {
    let a = line.iter().position(|c| *c == b' ')?;
    let rest = &line[a + 1..];
    let b = rest.iter().position(|c| *c == b' ')?;
    Some((&line[..a], &rest[..b], trim(&rest[b + 1..])))
}

/// A reply code begins a line as three digits followed by a space or a hyphen
/// (RFC 959 §4.2, RFC 5321 §4.2).
pub fn reply_code(line: &[u8]) -> Option<(u64, &[u8])> {
    if line.len() < 3 || !line[..3].iter().all(|c| c.is_ascii_digit()) {
        return None;
    }
    if line.len() > 3 && line[3] != b' ' && line[3] != b'-' {
        return None;
    }
    let n = line[..3]
        .iter()
        .fold(0u64, |a, c| a * 10 + (*c - b'0') as u64);
    Some((n, trim(line.get(4..).unwrap_or(&[]))))
}

/// One command line: the verb, then everything after it.
pub fn command(line: &[u8]) -> (&[u8], &[u8]) {
    match line.iter().position(|c| *c == b' ') {
        Some(i) => (&line[..i], trim(&line[i + 1..])),
        None => (line, &[]),
    }
}

/// FTP (RFC 959 §4) and SMTP (RFC 5321 §4) share a line grammar: a reply code
/// or an alphabetic verb. Anything else on those ports is the middle of a
/// stream, not the start of a message.
pub fn looks_like_control(data: &[u8]) -> bool {
    let Some(line) = lines(data).into_iter().next() else {
        return false;
    };
    if reply_code(line).is_some() {
        return true;
    }
    let (verb, _) = command(line);
    (3..=16).contains(&verb.len()) && verb.iter().all(|c| c.is_ascii_alphabetic())
}

pub fn control_items(data: &[u8]) -> Vec<Item> {
    let mut out = Vec::new();
    for line in lines(data) {
        if line.is_empty() {
            continue;
        }
        match reply_code(line) {
            Some((code, rest)) => {
                out.push(Item::uint("code", 0, code));
                out.push(named("text", rest));
            }
            None => {
                let (verb, arg) = command(line);
                out.push(named("command", verb));
                if !arg.is_empty() {
                    out.push(named("arg", arg));
                }
            }
        }
    }
    out
}

pub fn is_token(b: &[u8]) -> bool {
    !b.is_empty()
        && b.iter()
            .all(|c| c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(c))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_drop_their_terminators_and_keep_a_clipped_tail() {
        let got = lines(b"a\r\nbb\ncc");
        assert_eq!(got, vec![&b"a"[..], &b"bb"[..], &b"cc"[..]]);
    }

    #[test]
    fn a_header_block_ends_at_the_blank_line() {
        let msg = b"GET / HTTP/1.1\r\nHost: x\r\n\r\nbody";
        assert_eq!(&msg[headers_end(msg)..], b"body");
        assert_eq!(headers_end(b"GET / HTTP/1.1\r\nHost: x"), 23);
    }

    #[test]
    fn header_names_take_one_spelling_and_folds_are_joined() {
        let got = header_items(b"host: x.example\r\nCONTENT-TYPE: a\r\n\tb\r\n");
        assert_eq!(got[0].name, "Host");
        assert_eq!(got[0].value, ItemValue::Text("x.example".into()));
        assert_eq!(got[1].name, "Content-Type");
        assert_eq!(got[1].value, ItemValue::Text("a b".into()));
    }

    #[test]
    fn a_start_line_needs_all_three_parts() {
        assert!(start_line(b"GET / HTTP/1.1").is_some());
        assert!(start_line(b"GET /").is_none());
        assert!(start_line(b"\x17\x03\x03\x00\x20").is_none());
    }

    #[test]
    fn a_reply_code_is_three_digits_and_a_separator() {
        assert_eq!(reply_code(b"220 ready"), Some((220, &b"ready"[..])));
        assert_eq!(reply_code(b"250-first"), Some((250, &b"first"[..])));
        assert_eq!(reply_code(b"2200 x"), None);
        assert_eq!(reply_code(b"USER bob"), None);
    }

    #[test]
    fn a_command_splits_at_the_first_space() {
        assert_eq!(command(b"USER bob"), (&b"USER"[..], &b"bob"[..]));
        assert_eq!(command(b"QUIT"), (&b"QUIT"[..], &b""[..]));
    }

    #[test]
    fn binary_input_does_not_panic_or_allocate_without_bound() {
        let junk: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        assert!(lines(&junk).len() <= 256);
        let _ = header_items(&junk);
        let _ = headers_end(&junk);
    }

    #[test]
    fn a_block_that_never_terminates_is_the_whole_input() {
        let never = b"X: y\r\n".repeat(100_000);
        assert_eq!(headers_end(&never), never.len());
        assert_eq!(header_items(&never).len(), 256);
    }

    /// Folds append to one item, so the cap on lines is what bounds them.
    #[test]
    fn unending_continuation_lines_join_a_bounded_value() {
        let mut msg = b"X: a\r\n".to_vec();
        msg.extend(b" c\r\n".repeat(100_000));
        let got = header_items(&msg);
        assert_eq!(got.len(), 1);
        let ItemValue::Text(t) = &got[0].value else {
            panic!()
        };
        assert_eq!(t.len(), 1 + 2 * 255);
    }

    #[test]
    fn a_lone_cr_does_not_end_a_line() {
        assert_eq!(lines(b"a\rb\nc"), vec![&b"a\rb"[..], &b"c"[..]]);
        assert_eq!(headers_end(b"a\r\rb"), 4);
    }
}
