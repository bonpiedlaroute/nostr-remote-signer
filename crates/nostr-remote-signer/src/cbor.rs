//! A minimal CBOR reader and writer (RFC 8949), for the messages of the Nitro Secure Module
//! and its attestation documents.
//!
//! Definite lengths only, and no floats: neither occurs in those messages.

pub const BYTES: u8 = 2;
pub const TEXT: u8 = 3;
pub const MAP: u8 = 5;
pub const NULL: u8 = 0xf6;

/// One CBOR data item, borrowing its bytes and strings from the input.
#[derive(Debug, PartialEq)]
pub enum Cbor<'a> {
    Unsigned(u64),
    /// -1 - n
    Negative(u64),
    Bytes(&'a [u8]),
    Text(&'a str),
    Array(Vec<Cbor<'a>>),
    Map(Vec<(Cbor<'a>, Cbor<'a>)>),
    Tag(u64, Box<Cbor<'a>>),
    /// false, true, null, undefined
    Simple(u8),
}

/// Deep enough for an attestation document, shallow enough that no input can exhaust the
/// stack.
const MAX_DEPTH: usize = 16;

impl<'a> Cbor<'a> {
    /// Exactly one item, and nothing after it.
    pub fn parse(input: &'a [u8]) -> Option<Self> {
        let mut rest = input;
        let item = Self::read(&mut rest, 0)?;
        rest.is_empty().then_some(item)
    }

    fn read(input: &mut &'a [u8], depth: usize) -> Option<Self> {
        if depth > MAX_DEPTH {
            return None;
        }
        let (&first, mut rest) = input.split_first()?;
        let (major, info) = (first >> 5, first & 0x1f);
        let arg = match info {
            0..24 => u64::from(info),
            24..28 => {
                let (bytes, after) = rest.split_at_checked(1 << (info - 24))?;
                rest = after;
                bytes.iter().fold(0, |n, b| n << 8 | u64::from(*b))
            }
            // Indefinite lengths and reserved values.
            _ => return None,
        };

        let item = match major {
            0 => Cbor::Unsigned(arg),
            1 => Cbor::Negative(arg),
            BYTES | TEXT => {
                let (bytes, after) = rest.split_at_checked(usize::try_from(arg).ok()?)?;
                rest = after;
                if major == BYTES {
                    Cbor::Bytes(bytes)
                } else {
                    Cbor::Text(std::str::from_utf8(bytes).ok()?)
                }
            }
            4 => {
                let mut items = Vec::new();
                for _ in 0..arg {
                    items.push(Self::read(&mut rest, depth + 1)?);
                }
                Cbor::Array(items)
            }
            MAP => {
                let mut pairs = Vec::new();
                for _ in 0..arg {
                    let key = Self::read(&mut rest, depth + 1)?;
                    pairs.push((key, Self::read(&mut rest, depth + 1)?));
                }
                Cbor::Map(pairs)
            }
            6 => Cbor::Tag(arg, Box::new(Self::read(&mut rest, depth + 1)?)),
            _ => match info {
                20..24 => Cbor::Simple(info),
                _ => return None,
            },
        };
        *input = rest;
        Some(item)
    }

    /// The value under a text key, if this is a map.
    pub fn get(&self, key: &str) -> Option<&Cbor<'a>> {
        match self {
            Cbor::Map(pairs) => pairs
                .iter()
                .find_map(|(k, v)| (*k == Cbor::Text(key)).then_some(v)),
            _ => None,
        }
    }

    pub fn bytes(&self) -> Option<&'a [u8]> {
        match self {
            Cbor::Bytes(bytes) => Some(bytes),
            _ => None,
        }
    }

    pub fn text(&self) -> Option<&'a str> {
        match self {
            Cbor::Text(text) => Some(text),
            _ => None,
        }
    }
}

/// The head of an item: its major type, then its length or value in the shortest form.
pub fn write_head(out: &mut Vec<u8>, major: u8, n: u64) {
    let major = major << 5;
    match n {
        0..24 => out.push(major | n as u8),
        24..0x100 => out.extend([major | 24, n as u8]),
        0x100..0x1_0000 => {
            out.push(major | 25);
            out.extend((n as u16).to_be_bytes());
        }
        0x1_0000..0x1_0000_0000 => {
            out.push(major | 26);
            out.extend((n as u32).to_be_bytes());
        }
        _ => {
            out.push(major | 27);
            out.extend(n.to_be_bytes());
        }
    }
}

pub fn write_text(out: &mut Vec<u8>, text: &str) {
    write_head(out, TEXT, text.len() as u64);
    out.extend(text.as_bytes());
}

pub fn write_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    write_head(out, BYTES, bytes.len() as u64);
    out.extend(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_what_an_attestation_document_holds() {
        // 18([h'a1', {}, h'', h'']): COSE_Sign1 with a tag, as the NSM sends it, then a map
        // with every kind of item the document uses.
        let cose = [0xd2, 0x84, 0x41, 0xa1, 0xa0, 0x40, 0x40];
        assert_eq!(
            Cbor::parse(&cose),
            Some(Cbor::Tag(
                18,
                Box::new(Cbor::Array(vec![
                    Cbor::Bytes(&[0xa1]),
                    Cbor::Map(vec![]),
                    Cbor::Bytes(&[]),
                    Cbor::Bytes(&[]),
                ]))
            ))
        );

        let mut doc = Vec::new();
        write_head(&mut doc, MAP, 4);
        write_text(&mut doc, "timestamp");
        write_head(&mut doc, 0, 1_791_323_857_000);
        write_text(&mut doc, "pcrs");
        write_head(&mut doc, MAP, 1);
        write_head(&mut doc, 0, 0);
        write_bytes(&mut doc, &[7; 48]);
        write_text(&mut doc, "nonce");
        doc.push(NULL);
        write_text(&mut doc, "public_key");
        write_bytes(&mut doc, &[1; 300]);

        let doc = Cbor::parse(&doc).unwrap();
        assert_eq!(
            doc.get("timestamp"),
            Some(&Cbor::Unsigned(1_791_323_857_000))
        );
        assert_eq!(
            doc.get("pcrs"),
            Some(&Cbor::Map(vec![(Cbor::Unsigned(0), Cbor::Bytes(&[7; 48]))]))
        );
        assert_eq!(doc.get("nonce"), Some(&Cbor::Simple(22)));
        assert_eq!(
            doc.get("public_key").and_then(Cbor::bytes),
            Some(&[1; 300][..])
        );
        assert_eq!(doc.get("missing"), None);
    }

    #[test]
    fn writes_the_shortest_head() {
        for (n, expected) in [
            (23, vec![0x57]),
            (24, vec![0x58, 24]),
            (300, vec![0x59, 0x01, 0x2c]),
            (70_000, vec![0x5a, 0, 1, 0x11, 0x70]),
        ] {
            let mut out = Vec::new();
            write_head(&mut out, BYTES, n);
            assert_eq!(out, expected, "{n}");
        }
    }

    #[test]
    fn refuses_what_the_nsm_never_sends() {
        let mut doc = Vec::new();
        write_head(&mut doc, MAP, 1);
        write_text(&mut doc, "document");
        write_bytes(&mut doc, &[9; 100]);
        for len in 0..doc.len() {
            assert_eq!(Cbor::parse(&doc[..len]), None, "truncated at {len}");
        }
        assert_eq!(Cbor::parse(&[doc.as_slice(), &[0]].concat()), None);

        assert_eq!(
            Cbor::parse(&[0x5f, 0x41, 0, 0xff]),
            None,
            "indefinite length"
        );
        assert_eq!(Cbor::parse(&[0xf9, 0x3c, 0x00]), None, "a float");
        assert_eq!(
            Cbor::parse(&[0x62, 0xff, 0xfe]),
            None,
            "text that is not UTF-8"
        );
        assert_eq!(Cbor::parse(&[0x81].repeat(10_000)), None, "too deep");
        assert_eq!(
            Cbor::parse(&[0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
            None
        );
    }
}
