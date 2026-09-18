use std::borrow::Cow;

#[derive(Clone, Debug, PartialEq)]
pub enum ItemValue {
    /// Present with no payload (NOP, SAckOK, End of List).
    Flag,
    Uint(u64),
    Pair(u64, u64),
    /// RFC 2018 §3 SACK blocks.
    Pairs(Vec<(u64, u64)>),
    Bytes(Vec<u8>),
    Ipv4List(Vec<[u8; 4]>),
    Text(String),
    Items(Vec<Item>),
}

#[derive(Clone, Debug, PartialEq)]
pub struct Item {
    /// Conventional name where the code is known, otherwise a numeric label.
    pub name: Cow<'static, str>,
    pub code: u32,
    pub value: ItemValue,
}

impl Item {
    pub fn named(name: &'static str, code: u32, value: ItemValue) -> Self {
        Self {
            name: Cow::Borrowed(name),
            code,
            value,
        }
    }

    pub fn flag(name: &'static str, code: u32) -> Self {
        Self::named(name, code, ItemValue::Flag)
    }

    pub fn uint(name: &'static str, code: u32, v: u64) -> Self {
        Self::named(name, code, ItemValue::Uint(v))
    }

    pub fn pair(name: &'static str, code: u32, a: u64, b: u64) -> Self {
        Self::named(name, code, ItemValue::Pair(a, b))
    }

    pub fn bytes(name: &'static str, code: u32, b: &[u8]) -> Self {
        Self::named(name, code, ItemValue::Bytes(b.to_vec()))
    }

    pub fn unknown(code: u32, b: &[u8]) -> Self {
        Self {
            name: Cow::Owned(code.to_string()),
            code,
            value: ItemValue::Bytes(b.to_vec()),
        }
    }
}

/// A value offered for encoding, before the table decides what shape it takes.
/// `Text` covers a dotted quad, a symbolic name and a string payload alike.
#[derive(Clone, Debug, PartialEq)]
pub enum OptArg {
    Flag,
    Uint(u64),
    Bytes(Vec<u8>),
    Text(String),
    List(Vec<OptArg>),
}

/// No real option value nests deeper than a list of pairs, and `num_value`,
/// `push_addrs` and `flat_bytes` all walk a `List` by recursion, so the shape
/// is bounded once here rather than guarded in each of them.
pub const MAX_ARG_DEPTH: usize = 8;

impl OptArg {
    /// Iterative on purpose: measuring a deep value must not itself overflow
    /// the stack.
    pub fn nests_deeper_than(&self, limit: usize) -> bool {
        let mut stack = vec![(self, 1usize)];
        while let Some((arg, depth)) = stack.pop() {
            if depth > limit {
                return true;
            }
            if let OptArg::List(v) = arg {
                stack.extend(v.iter().map(|e| (e, depth + 1)));
            }
        }
        false
    }
}

/// The payload layout of one option, read in both directions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shape {
    /// One octet: no length octet and no payload.
    Bare,
    /// A length octet despite an empty payload. SAckOK is this and not `Bare`;
    /// emitting it bare desynchronises every option after it.
    Empty,
    /// Big-endian integer; a payload of another width decodes as raw bytes.
    Uint(usize),
    /// Big-endian integer, decoded from whatever width arrived.
    LooseUint(usize),
    /// Two big-endian 32-bit words.
    Pair,
    PairList,
    Bytes,
    Ipv4List,
    Text,
}

impl Shape {
    /// Octets an integer value takes when this shape is asked to hold one.
    const fn width(self) -> usize {
        match self {
            Shape::Uint(w) | Shape::LooseUint(w) => w,
            Shape::Pair | Shape::PairList => 8,
            Shape::Ipv4List => 4,
            Shape::Bytes | Shape::Text => 1,
            Shape::Bare | Shape::Empty => 0,
        }
    }
}

pub struct OptDesc {
    pub name: &'static str,
    pub code: u8,
    pub shape: Shape,
    /// Symbolic values accepted in place of the integer (DHCP message types).
    pub names: &'static [(&'static str, u64)],
    /// No such table nests one of its own, so a walk descends exactly one
    /// level.
    pub sub: Option<&'static OptTable>,
}

impl OptDesc {
    pub const fn new(name: &'static str, code: u8, shape: Shape) -> Self {
        Self {
            name,
            code,
            shape,
            names: &[],
            sub: None,
        }
    }

    pub const fn with_names(mut self, names: &'static [(&'static str, u64)]) -> Self {
        self.names = names;
        self
    }

    pub const fn nesting(mut self, t: &'static OptTable) -> Self {
        self.sub = Some(t);
        self
    }
}

/// What the length octet counts. TCP (RFC 9293 §3.1) and IPv4 (RFC 791 §3.1)
/// count the code and length octets themselves, so the payload is `len - 2`;
/// DHCP (RFC 2132 §2) counts only the option data. Applying one rule to the
/// other silently mis-codes every option that follows rather than failing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LenRule {
    WithHeader,
    PayloadOnly,
}

/// One table per protocol, serving decode and encode alike.
pub struct OptTable {
    pub proto: &'static str,
    pub rule: LenRule,
    /// The code that closes the region. `WithHeader` stops before it;
    /// `PayloadOnly` emits it first, since RFC 2132 §3.2 End is an option.
    pub end: Option<u8>,
    pub opts: &'static [OptDesc],
}

impl OptTable {
    pub fn by_code(&self, code: u8) -> Option<&OptDesc> {
        self.opts.iter().find(|d| d.code == code)
    }

    pub fn by_name(&self, name: &str) -> Option<&OptDesc> {
        self.opts.iter().find(|d| d.name == name)
    }

    fn is_bare(&self, code: u8) -> bool {
        self.by_code(code).is_some_and(|d| d.shape == Shape::Bare)
    }

    pub fn decode(&self, code: u8, p: &[u8]) -> Item {
        let Some(d) = self.by_code(code) else {
            return Item::unknown(code as u32, p);
        };
        let c = code as u32;
        if let Some(t) = d.sub {
            return Item::named(d.name, c, ItemValue::Items(t.walk(p)));
        }
        match d.shape {
            Shape::Bare | Shape::Empty => Item::flag(d.name, c),
            Shape::Uint(w) if p.len() == w => Item::uint(d.name, c, be(p)),
            // The capture disagrees with the registry; keep the raw payload.
            Shape::Uint(_) => Item::bytes(d.name, c, p),
            Shape::LooseUint(_) => Item::uint(d.name, c, be(p)),
            Shape::Pair if p.len() == 8 => Item::pair(d.name, c, be(&p[..4]), be(&p[4..])),
            Shape::PairList if !p.is_empty() && p.len() % 8 == 0 => {
                Item::named(d.name, c, ItemValue::Pairs(pairs(p)))
            }
            Shape::Pair | Shape::PairList | Shape::Bytes => Item::bytes(d.name, c, p),
            Shape::Ipv4List => Item::named(d.name, c, ItemValue::Ipv4List(addrs(p))),
            Shape::Text => Item::named(
                d.name,
                c,
                ItemValue::Text(String::from_utf8_lossy(p).into_owned()),
            ),
        }
    }

    /// Malformed input stops the walk rather than erroring: truncation is
    /// normal on a snaplen-clipped capture.
    pub fn walk(&self, data: &[u8]) -> Vec<Item> {
        self.walk_raw(data)
            .into_iter()
            .map(|(code, p)| self.decode(code, p))
            .collect()
    }

    /// One code and one borrowed payload per option. RFC 3396 joining needs the
    /// octets as the wire carried them, before any shape has been imposed.
    pub fn walk_raw<'a>(&self, data: &'a [u8]) -> Vec<(u8, &'a [u8])> {
        let mut out = Vec::new();
        let mut i = 0usize;
        // Bound the walk: a zero-length option would otherwise spin forever.
        let mut guard = 0;
        while i < data.len() && guard < 512 {
            guard += 1;
            let code = data[i];
            if self.rule == LenRule::WithHeader && Some(code) == self.end {
                break;
            }
            if self.is_bare(code) {
                out.push((code, &data[i..i]));
                i += 1;
                if Some(code) == self.end {
                    break;
                }
                continue;
            }
            if i + 1 >= data.len() {
                break;
            }
            let len = data[i + 1] as usize;
            let next = match self.rule {
                LenRule::WithHeader if len < 2 => break,
                LenRule::WithHeader => i + len,
                LenRule::PayloadOnly => i + 2 + len,
            };
            if next > data.len() {
                break;
            }
            out.push((code, &data[i + 2..next]));
            i = next;
        }
        out
    }

    /// Resolves a name — or a decimal code for an option this table does not
    /// name — and coerces the value into the shape that name implies.
    pub fn item(&self, name: &str, arg: &OptArg) -> Result<Item, String> {
        if arg.nests_deeper_than(MAX_ARG_DEPTH) {
            return Err(format!(
                "{} option {name:?} value nests more than {MAX_ARG_DEPTH} deep",
                self.proto
            ));
        }
        if let Some(d) = self.by_name(name) {
            return Ok(Item {
                name: Cow::Borrowed(d.name),
                code: d.code as u32,
                value: match d.sub {
                    Some(t) => sub_value(t, arg)?,
                    None => value_of(d.shape, d.names, arg)?,
                },
            });
        }
        if let Ok(code) = name.parse::<u8>() {
            return Ok(Item {
                name: Cow::Owned(name.to_string()),
                code: code as u32,
                value: value_of(Shape::Bytes, &[], arg)?,
            });
        }
        Err(format!("unknown {} option {name:?}", self.proto))
    }

    /// The inverse of `walk`.
    pub fn encode(&self, items: &[Item]) -> Result<Vec<u8>, String> {
        let mut out = Vec::new();
        for it in items {
            let code = u8::try_from(it.code)
                .map_err(|_| format!("{} option code {} is out of range", self.proto, it.code))?;
            let d = self.by_code(code);
            let shape = d.map_or(Shape::Bytes, |d| d.shape);
            if shape == Shape::Bare {
                out.push(code);
                continue;
            }
            let p = match (d.and_then(|d| d.sub), &it.value) {
                (Some(t), ItemValue::Items(v)) => t.encode(v)?,
                _ => payload(shape, &it.value),
            };
            let len = match self.rule {
                LenRule::WithHeader => p.len() + 2,
                LenRule::PayloadOnly => p.len(),
            };
            if len > 255 {
                return Err(format!(
                    "{} option {:?} is too long to encode",
                    self.proto, it.name
                ));
            }
            out.push(code);
            out.push(len as u8);
            out.extend_from_slice(&p);
        }
        Ok(out)
    }

    /// Encode an option region from named values, the way a caller types them:
    /// `[("MSS", OptArg::Uint(1460)), ("SAckOK", OptArg::Flag)]`.
    pub fn build<S: AsRef<str>>(&self, opts: &[(S, OptArg)]) -> Result<Vec<u8>, String> {
        let items = opts
            .iter()
            .map(|(n, v)| self.item(n.as_ref(), v))
            .collect::<Result<Vec<_>, _>>()?;
        self.encode(&items)
    }
}

fn payload(shape: Shape, v: &ItemValue) -> Vec<u8> {
    if matches!(shape, Shape::Bare | Shape::Empty) {
        return Vec::new();
    }
    match v {
        ItemValue::Flag => Vec::new(),
        ItemValue::Uint(n) => be_bytes(*n, shape.width()),
        ItemValue::Pair(a, b) => {
            let mut out = be_bytes(*a, 4);
            out.extend_from_slice(&be_bytes(*b, 4));
            out
        }
        ItemValue::Pairs(l) => l
            .iter()
            .flat_map(|(a, b)| [be_bytes(*a, 4), be_bytes(*b, 4)].concat())
            .collect(),
        ItemValue::Bytes(b) => b.clone(),
        ItemValue::Ipv4List(l) => l.concat(),
        ItemValue::Text(s) => s.as_bytes().to_vec(),
        ItemValue::Items(_) => Vec::new(),
    }
}

fn value_of(shape: Shape, names: &[(&str, u64)], arg: &OptArg) -> Result<ItemValue, String> {
    match shape {
        Shape::Bare | Shape::Empty => Ok(ItemValue::Flag),
        Shape::Uint(_) | Shape::LooseUint(_) | Shape::Pair => num_value(shape, names, arg),
        Shape::PairList => pair_value(arg),
        Shape::Ipv4List => ip_value(arg),
        Shape::Text | Shape::Bytes => Ok(ItemValue::Bytes(flat_bytes(arg))),
    }
}

/// Accepts what the parse produced: (name, value) pairs. Anything else is raw
/// octets.
fn sub_value(t: &'static OptTable, arg: &OptArg) -> Result<ItemValue, String> {
    let OptArg::List(entries) = arg else {
        return Ok(ItemValue::Bytes(flat_bytes(arg)));
    };
    let mut items = Vec::with_capacity(entries.len());
    for e in entries {
        let named = match e {
            OptArg::List(pair) => match pair.as_slice() {
                [OptArg::Text(n), v] => Some(t.item(n, v)?),
                [OptArg::Text(n)] => Some(t.item(n, &OptArg::Flag)?),
                _ => None,
            },
            _ => None,
        };
        match named {
            Some(i) => items.push(i),
            None => return Ok(ItemValue::Bytes(flat_bytes(arg))),
        }
    }
    Ok(ItemValue::Items(items))
}

fn pair_value(arg: &OptArg) -> Result<ItemValue, String> {
    if let OptArg::Bytes(b) = arg {
        return Ok(ItemValue::Bytes(b.clone()));
    }
    let mut edges = Vec::new();
    push_uints(arg, &mut edges)?;
    if edges.len() % 2 != 0 {
        return Err("a block takes a left and a right edge".into());
    }
    Ok(ItemValue::Pairs(
        edges.chunks_exact(2).map(|c| (c[0], c[1])).collect(),
    ))
}

fn push_uints(arg: &OptArg, out: &mut Vec<u64>) -> Result<(), String> {
    match arg {
        OptArg::Flag => {}
        OptArg::Uint(n) => out.push(*n),
        OptArg::Text(s) => out.push(
            s.parse::<u64>()
                .map_err(|_| format!("cannot encode {s:?} as an edge"))?,
        ),
        OptArg::Bytes(b) => out.extend(b.chunks_exact(4).map(be)),
        OptArg::List(v) => {
            for e in v {
                push_uints(e, out)?;
            }
        }
    }
    Ok(())
}

fn num_value(shape: Shape, names: &[(&str, u64)], arg: &OptArg) -> Result<ItemValue, String> {
    match arg {
        OptArg::Flag => Ok(ItemValue::Uint(0)),
        OptArg::Uint(n) => Ok(ItemValue::Uint(*n)),
        OptArg::Bytes(b) => Ok(ItemValue::Bytes(b.clone())),
        OptArg::Text(s) => names
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(s))
            .map(|(_, v)| ItemValue::Uint(*v))
            .or_else(|| s.parse::<u64>().ok().map(ItemValue::Uint))
            .ok_or_else(|| format!("cannot encode {s:?} as a number")),
        OptArg::List(v) => match v.as_slice() {
            [one] => num_value(shape, names, one),
            [OptArg::Uint(a), OptArg::Uint(b)] if shape == Shape::Pair => {
                Ok(ItemValue::Pair(*a, *b))
            }
            _ => {
                let mut out = Vec::new();
                for e in v {
                    match e {
                        OptArg::Uint(n) => out.extend_from_slice(&be_bytes(*n, 4)),
                        _ => return Err("cannot encode a mixed list as a number".into()),
                    }
                }
                Ok(ItemValue::Bytes(out))
            }
        },
    }
}

fn ip_value(arg: &OptArg) -> Result<ItemValue, String> {
    let mut out = Vec::new();
    push_addrs(arg, &mut out)?;
    Ok(if out.len() % 4 == 0 {
        ItemValue::Ipv4List(addrs(&out))
    } else {
        ItemValue::Bytes(out)
    })
}

fn push_addrs(arg: &OptArg, out: &mut Vec<u8>) -> Result<(), String> {
    match arg {
        OptArg::Flag => {}
        OptArg::Uint(n) => out.extend_from_slice(&be_bytes(*n, 4)),
        OptArg::Bytes(b) => out.extend_from_slice(b),
        OptArg::Text(s) => {
            let a = crate::parse::ipv4(s).ok_or_else(|| format!("{s:?} is not an IPv4 address"))?;
            out.extend_from_slice(&a);
        }
        OptArg::List(v) => {
            for e in v {
                push_addrs(e, out)?;
            }
        }
    }
    Ok(())
}

/// An integer stands for one octet here, which is what a DHCP parameter
/// request list is a list of.
fn flat_bytes(arg: &OptArg) -> Vec<u8> {
    match arg {
        OptArg::Flag => Vec::new(),
        OptArg::Uint(n) => vec![*n as u8],
        OptArg::Bytes(b) => b.clone(),
        OptArg::Text(s) => s.as_bytes().to_vec(),
        OptArg::List(v) => v.iter().flat_map(flat_bytes).collect(),
    }
}

/// RFC 2132 address options have a length that is a multiple of four, so a
/// trailing partial address is malformed and dropped.
fn addrs(p: &[u8]) -> Vec<[u8; 4]> {
    p.chunks_exact(4)
        .map(|c| [c[0], c[1], c[2], c[3]])
        .collect()
}

fn pairs(p: &[u8]) -> Vec<(u64, u64)> {
    p.chunks_exact(8)
        .map(|c| (be(&c[..4]), be(&c[4..])))
        .collect()
}

fn be_bytes(v: u64, width: usize) -> Vec<u8> {
    v.to_be_bytes()[8 - width.min(8)..].to_vec()
}

pub(crate) fn be(b: &[u8]) -> u64 {
    let mut v = 0u64;
    for x in b.iter().take(8) {
        v = (v << 8) | *x as u64;
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    const TLV: OptTable = OptTable {
        proto: "T",
        rule: LenRule::WithHeader,
        end: Some(0),
        opts: &[
            OptDesc::new("NOP", 1, Shape::Bare),
            OptDesc::new("MSS", 2, Shape::Uint(2)),
            OptDesc::new("WScale", 3, Shape::Uint(1)),
        ],
    };

    #[test]
    fn walks_a_simple_tlv_run() {
        let items = TLV.walk(&[2u8, 4, 0x05, 0xb4, 1, 3, 3, 7]);
        assert_eq!(items.len(), 3);
        assert_eq!(items[0].value, ItemValue::Uint(0x05b4));
        assert_eq!(items[1].value, ItemValue::Flag);
        assert_eq!(items[2].value, ItemValue::Uint(7));
    }

    #[test]
    fn stops_at_end_code() {
        let items = TLV.walk(&[2u8, 4, 0x05, 0xb4, 0, 9, 9, 9]);
        assert_eq!(items.len(), 1);
    }

    #[test]
    fn truncated_option_stops_cleanly() {
        assert!(TLV.walk(&[2u8, 8, 0x05, 0xb4]).is_empty());
    }

    #[test]
    fn zero_length_does_not_hang() {
        assert!(TLV.walk(&[2u8, 0, 2, 0, 2, 0]).is_empty());
    }

    #[test]
    fn be_reads_widths() {
        assert_eq!(be(&[0x01]), 1);
        assert_eq!(be(&[0x05, 0xb4]), 1460);
        assert_eq!(be(&[0, 0, 0, 1]), 1);
        assert_eq!(be(&[]), 0);
    }

    #[test]
    fn a_decimal_name_encodes_as_that_code() {
        let b = TLV.build(&[("99", OptArg::Bytes(vec![0xaa]))]).unwrap();
        assert_eq!(b, vec![99, 3, 0xaa]);
    }

    #[test]
    fn an_unknown_name_is_rejected() {
        assert!(TLV.build(&[("NoSuchOption", OptArg::Flag)]).is_err());
        assert!(TLV.build(&[("256", OptArg::Flag)]).is_err());
    }

    #[test]
    fn an_oversized_payload_is_rejected() {
        let long = OptArg::Bytes(vec![0u8; 254]);
        assert!(TLV.build(&[("99", long)]).is_err());
    }

    fn nested(depth: usize) -> OptArg {
        (0..depth).fold(OptArg::Uint(1), |a, _| OptArg::List(vec![a]))
    }

    #[test]
    fn a_shallow_nested_value_still_encodes() {
        assert_eq!(
            TLV.build(&[("MSS", nested(MAX_ARG_DEPTH - 1))]).unwrap(),
            vec![2, 4, 0, 1]
        );
    }

    #[test]
    fn a_deeply_nested_value_is_rejected_not_recursed() {
        let deep = nested(MAX_ARG_DEPTH + 1);
        assert!(deep.nests_deeper_than(MAX_ARG_DEPTH));
        assert!(TLV.build(&[("MSS", deep)]).is_err());
        assert!(TLV.build(&[("99", nested(MAX_ARG_DEPTH * 10))]).is_err());
    }

    #[test]
    fn a_wide_but_shallow_value_is_accepted() {
        let wide = OptArg::List((0..1000).map(|_| OptArg::Uint(1)).collect());
        assert!(!wide.nests_deeper_than(MAX_ARG_DEPTH));
    }

    fn sample(d: &OptDesc) -> Vec<u8> {
        if let Some(t) = d.sub {
            let first = t.opts.first().expect("a nested table names something");
            return t
                .encode(&[t.decode(first.code, &sample(first))])
                .expect("a nested sample encodes");
        }
        match d.shape {
            Shape::Bare | Shape::Empty => vec![],
            Shape::Uint(w) | Shape::LooseUint(w) => vec![1u8; w],
            Shape::Pair | Shape::PairList => vec![0, 0, 0, 1, 0, 0, 0, 2],
            Shape::Bytes => vec![0xaa, 0xbb],
            Shape::Ipv4List => vec![10, 0, 0, 1],
            Shape::Text => b"lan".to_vec(),
        }
    }

    /// Encoding what a walk produced must reproduce exactly those items, for
    /// every option either direction names.
    fn assert_round_trips(table: &OptTable) {
        let (closing, body): (Vec<_>, Vec<_>) =
            table.opts.iter().partition(|d| Some(d.code) == table.end);
        let mut items: Vec<Item> = body
            .iter()
            .map(|d| table.decode(d.code, &sample(d)))
            .collect();
        // A closing code ends the region, so it can only come last, and only
        // where the walk emits it at all.
        if table.rule == LenRule::PayloadOnly {
            items.extend(closing.iter().map(|d| table.decode(d.code, &[])));
        }
        let bytes = table.encode(&items).expect("every named option encodes");
        assert_eq!(table.walk(&bytes), items, "{} round trip", table.proto);
    }

    #[test]
    fn every_named_option_round_trips() {
        assert_round_trips(&crate::layers::tcp::OPTIONS);
        assert_round_trips(&crate::layers::ipv4::OPTIONS);
        assert_round_trips(&crate::layers::bootp::DHCP_OPTIONS);
    }

    /// `walk` descends into `sub` without a depth counter, so the tables must
    /// not nest one that nests another.
    #[test]
    fn a_nested_option_table_nests_nothing_itself() {
        for t in [
            &crate::layers::tcp::OPTIONS,
            &crate::layers::ipv4::OPTIONS,
            &crate::layers::bootp::DHCP_OPTIONS,
            &crate::layers::bootp::RELAY_OPTIONS,
        ] {
            for d in t.opts {
                let Some(sub) = d.sub else { continue };
                for inner in sub.opts {
                    assert!(
                        inner.sub.is_none(),
                        "{}.{} nests {}.{}, more than one level",
                        t.proto,
                        d.name,
                        sub.proto,
                        inner.name
                    );
                }
            }
        }
    }

    #[test]
    fn the_two_length_conventions_differ() {
        use crate::layers::{bootp::DHCP_OPTIONS, tcp};
        // Both payloads are two octets; only TCP's length octet counts the
        // code and length octets as well.
        let mss = tcp::OPTIONS.build(&[("MSS", OptArg::Uint(1460))]).unwrap();
        assert_eq!(mss, vec![2, 4, 0x05, 0xb4]);
        let size = DHCP_OPTIONS
            .build(&[("max_dhcp_size", OptArg::Uint(1500))])
            .unwrap();
        assert_eq!(size, vec![57, 2, 0x05, 0xdc]);
    }
}
