#![expect(
    clippy::panic,
    reason = "vendored from upstream `h2`: matches upstream invariant-violation panicking style"
)]

use super::table::{Index, Table};
use super::{Header, header::Name, huffman};

use rama_core::bytes::{BufMut, BytesMut};
use rama_core::telemetry::tracing;

use crate::header::{self, HeaderName, HeaderValue};

#[derive(Debug)]
pub struct Encoder {
    table: Table,
    size_update: Option<SizeUpdate>,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum SizeUpdate {
    One(usize),
    Two(usize, usize), // min, max
}

impl Encoder {
    #[must_use]
    pub fn new(max_size: usize, capacity: usize) -> Self {
        Self {
            table: Table::new(max_size, capacity),
            size_update: None,
        }
    }

    /// Queues a max size update.
    ///
    /// The next call to `encode` will include a dynamic size update frame.
    pub fn update_max_size(&mut self, val: usize) {
        match self.size_update {
            Some(SizeUpdate::One(old)) => {
                if val > old {
                    if old > self.table.max_size() {
                        self.size_update = Some(SizeUpdate::One(val));
                    } else {
                        self.size_update = Some(SizeUpdate::Two(old, val));
                    }
                } else {
                    self.size_update = Some(SizeUpdate::One(val));
                }
            }
            Some(SizeUpdate::Two(min, _)) => {
                if val < min {
                    self.size_update = Some(SizeUpdate::One(val));
                } else {
                    self.size_update = Some(SizeUpdate::Two(min, val));
                }
            }
            None => {
                if val != self.table.max_size() {
                    // Don't bother writing a frame if the value already matches
                    // the table's max size.
                    self.size_update = Some(SizeUpdate::One(val));
                }
            }
        }
    }

    /// Encode a set of headers into the provide buffer
    pub fn encode<I>(&mut self, headers: I, dst: &mut BytesMut)
    where
        I: IntoIterator<Item = Header<Option<HeaderName>>>,
    {
        self.encode_with_policy(headers, dst, false);
    }

    pub(crate) fn encode_with_policy<I>(
        &mut self,
        headers: I,
        dst: &mut BytesMut,
        chrome_indexing: bool,
    ) where
        I: IntoIterator<Item = Header<Option<HeaderName>>>,
    {
        let span = tracing::trace_span!("hpack::encode");
        let _e = span.enter();

        self.encode_size_updates(dst);

        let mut last_index = None;

        for header in headers {
            if chrome_indexing && let Some(crumbs) = chrome_cookie_crumbs(&header) {
                for crumb in crumbs {
                    self.encode_one(crumb, dst, chrome_indexing, &mut last_index);
                }
            } else {
                self.encode_one(header, dst, chrome_indexing, &mut last_index);
            }
        }
    }

    fn encode_one(
        &mut self,
        header: Header<Option<HeaderName>>,
        dst: &mut BytesMut,
        chrome_indexing: bool,
        last_index: &mut Option<Index>,
    ) {
        match header.reify() {
            // The header has an associated name. In which case, try to
            // index it in the table.
            Ok(header) => {
                let index = self.table.index_with_policy(header, chrome_indexing);
                self.encode_header(&index, dst);

                *last_index = Some(index);
            }
            // The header does not have an associated name. This means that
            // the name is the same as the previously yielded header. In
            // which case, we skip table lookup and just use the same index
            // as the previous entry.
            Err(value) => {
                self.encode_header_without_name(
                    last_index.as_ref().unwrap_or_else(|| {
                        panic!(
                            "encoding header without name, but no previous index to use for name"
                        );
                    }),
                    &value,
                    dst,
                );
            }
        }
    }

    fn encode_size_updates(&mut self, dst: &mut BytesMut) {
        match self.size_update.take() {
            Some(SizeUpdate::One(val)) => {
                self.table.resize(val);
                encode_size_update(val, dst);
            }
            Some(SizeUpdate::Two(min, max)) => {
                self.table.resize(min);
                self.table.resize(max);
                encode_size_update(min, dst);
                encode_size_update(max, dst);
            }
            None => {}
        }
    }

    fn encode_header(&self, index: &Index, dst: &mut BytesMut) {
        match *index {
            Index::Indexed(idx, _) => {
                encode_int(idx, 7, 0x80, dst);
            }
            Index::Name(idx, _) => {
                let header = self.table.resolve(index);

                encode_not_indexed(idx, header.value_slice(), header.is_sensitive(), dst);
            }
            Index::Inserted(_) => {
                let header = self.table.resolve(index);

                assert!(!header.is_sensitive());

                dst.put_u8(0b0100_0000);

                encode_name(header.name(), dst);
                encode_str(header.value_slice(), dst);
            }
            Index::InsertedValue(idx, _) => {
                let header = self.table.resolve(index);

                assert!(!header.is_sensitive());

                encode_int(idx, 6, 0b0100_0000, dst);
                encode_str(header.value_slice(), dst);
            }
            Index::NotIndexed(_) => {
                let header = self.table.resolve(index);

                encode_not_indexed2(
                    header.name(),
                    header.value_slice(),
                    header.is_sensitive(),
                    dst,
                );
            }
        }
    }

    fn encode_header_without_name(&self, last: &Index, value: &HeaderValue, dst: &mut BytesMut) {
        match *last {
            Index::Indexed(..)
            | Index::Name(..)
            | Index::Inserted(..)
            | Index::InsertedValue(..) => {
                let idx = self.table.resolve_idx(last);

                encode_not_indexed(idx, value.as_ref(), value.is_sensitive(), dst);
            }
            Index::NotIndexed(_) => {
                let last = self.table.resolve(last);

                encode_not_indexed2(last.name(), value.as_ref(), value.is_sensitive(), dst);
            }
        }
    }
}

/// Expand one RFC 6265 Cookie row into Chromium's HTTP/2 HPACK crumbs.
///
/// This runs inside the H2 encoder, after protocol selection and immediately
/// before table lookup.  The request HeaderMap is therefore unchanged and an
/// HTTP/1.x fallback retains its single Cookie field.  Malformed rows and
/// already singular rows are left byte-for-byte unchanged.
fn chrome_cookie_crumbs(
    header: &Header<Option<HeaderName>>,
) -> Option<Vec<Header<Option<HeaderName>>>> {
    let Header::Field {
        name: Some(name),
        value,
    } = header
    else {
        return None;
    };
    if name != header::COOKIE || !value.as_bytes().contains(&b';') {
        return None;
    }

    let raw_crumbs = value
        .as_bytes()
        .split(|byte| *byte == b';')
        .map(trim_cookie_ows)
        .collect::<Vec<_>>();
    if raw_crumbs.iter().any(|crumb| {
        let Some(separator) = crumb.iter().position(|byte| *byte == b'=') else {
            return true;
        };
        !valid_cookie_name(&crumb[..separator]) || !valid_cookie_value(&crumb[separator + 1..])
    }) {
        return None;
    }

    let sensitive = value.is_sensitive();
    raw_crumbs
        .into_iter()
        .map(|crumb| {
            let mut value = HeaderValue::from_bytes(crumb).ok()?;
            value.set_sensitive(sensitive);
            Some(Header::Field {
                name: Some(name.clone()),
                value,
            })
        })
        .collect()
}

fn trim_cookie_ows(mut value: &[u8]) -> &[u8] {
    while value
        .first()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        value = &value[1..];
    }
    while value
        .last()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        value = &value[..value.len() - 1];
    }
    value
}

fn valid_cookie_name(value: &[u8]) -> bool {
    const SEPARATORS: &[u8] = b"()<>@,;:\\\"/[]?={} \t";
    !value.is_empty()
        && value
            .iter()
            .all(|byte| (0x21..=0x7e).contains(byte) && !SEPARATORS.contains(byte))
}

fn valid_cookie_value(value: &[u8]) -> bool {
    let value = match value {
        [b'"', inner @ .., b'"'] => inner,
        _ if value.contains(&b'"') => return false,
        _ => value,
    };
    value.iter().all(|byte| {
        matches!(
            byte,
            0x21 | 0x23..=0x2b | 0x2d..=0x3a | 0x3c..=0x5b | 0x5d..=0x7e
        )
    })
}

impl Default for Encoder {
    fn default() -> Self {
        Self::new(4096, 0)
    }
}

fn encode_size_update(val: usize, dst: &mut BytesMut) {
    encode_int(val, 5, 0b0010_0000, dst)
}

fn encode_not_indexed(name: usize, value: &[u8], sensitive: bool, dst: &mut BytesMut) {
    if sensitive {
        encode_int(name, 4, 0b10000, dst);
    } else {
        encode_int(name, 4, 0, dst);
    }

    encode_str(value, dst);
}

fn encode_not_indexed2(name: Name<'_>, value: &[u8], sensitive: bool, dst: &mut BytesMut) {
    if sensitive {
        dst.put_u8(0b10000);
    } else {
        dst.put_u8(0);
    }

    encode_name(name, dst);
    encode_str(value, dst);
}

fn encode_name(name: Name<'_>, dst: &mut BytesMut) {
    match name {
        Name::Field(name) => encode_header_name(name, dst),
        name => encode_str(name.as_slice(), dst),
    }
}

fn encode_header_name(name: &HeaderName, dst: &mut BytesMut) {
    let bytes = name.as_str().as_bytes();
    if bytes.iter().any(u8::is_ascii_uppercase) {
        encode_str_lowercase_ascii(bytes, dst);
    } else {
        encode_str(bytes, dst);
    }
}

fn encode_str(val: &[u8], dst: &mut BytesMut) {
    if !val.is_empty() {
        let idx = position(dst);

        // Push a placeholder byte for the length header
        dst.put_u8(0);

        // Encode with huffman
        huffman::encode(val, dst);

        finish_encoded_str(idx, dst);
    } else {
        // Write an empty string
        dst.put_u8(0);
    }
}

fn encode_str_lowercase_ascii(val: &[u8], dst: &mut BytesMut) {
    if !val.is_empty() {
        let idx = position(dst);

        // Push a placeholder byte for the length header
        dst.put_u8(0);

        // Encode with huffman while lowercasing ASCII header-name bytes
        huffman::encode_lowercase_ascii(val, dst);

        finish_encoded_str(idx, dst);
    } else {
        // Write an empty string
        dst.put_u8(0);
    }
}

fn finish_encoded_str(idx: usize, dst: &mut BytesMut) {
    let huff_len = position(dst) - (idx + 1);

    if encode_int_one_byte(huff_len, 7) {
        // Write the string head
        dst[idx] = 0x80 | huff_len as u8;
    } else {
        // Write the head to a placeholder
        const PLACEHOLDER_LEN: usize = 8;
        let mut buf = [0u8; PLACEHOLDER_LEN];

        let head_len = {
            let mut head_dst = &mut buf[..];
            encode_int(huff_len, 7, 0x80, &mut head_dst);
            PLACEHOLDER_LEN - head_dst.remaining_mut()
        };

        // This is just done to reserve space in the destination
        dst.put_slice(&buf[1..head_len]);

        // Shift the header forward
        for i in 0..huff_len {
            let src_i = idx + 1 + (huff_len - (i + 1));
            let dst_i = idx + head_len + (huff_len - (i + 1));
            dst[dst_i] = dst[src_i];
        }

        // Copy in the head
        for i in 0..head_len {
            dst[idx + i] = buf[i];
        }
    }
}

/// Encode an integer into the given destination buffer
fn encode_int<B: BufMut>(
    mut value: usize,   // The integer to encode
    prefix_bits: usize, // The number of bits in the prefix
    first_byte: u8,     // The base upon which to start encoding the int
    dst: &mut B,
) {
    if encode_int_one_byte(value, prefix_bits) {
        dst.put_u8(first_byte | value as u8);
        return;
    }

    let low = (1 << prefix_bits) - 1;

    value -= low;

    dst.put_u8(first_byte | low as u8);

    while value >= 128 {
        dst.put_u8(0b1000_0000 | value as u8);

        value >>= 7;
    }

    dst.put_u8(value as u8);
}

/// Returns true if the in the int can be fully encoded in the first byte.
fn encode_int_one_byte(value: usize, prefix_bits: usize) -> bool {
    value < (1 << prefix_bits) - 1
}

fn position(buf: &BytesMut) -> usize {
    buf.len()
}

#[cfg(test)]
mod test {
    use super::super::Decoder;
    use super::*;
    use crate::{HeaderValue, Method};
    use std::{io::Cursor, ops::ControlFlow};

    #[test]
    fn test_encode_method_get() {
        let mut encoder = Encoder::default();
        let res = encode(&mut encoder, vec![method("GET")]);
        assert_eq!(*res, [0x80 | 2]);
        assert_eq!(encoder.table.len(), 0);
    }

    #[test]
    fn test_encode_method_post() {
        let mut encoder = Encoder::default();
        let res = encode(&mut encoder, vec![method("POST")]);
        assert_eq!(*res, [0x80 | 3]);
        assert_eq!(encoder.table.len(), 0);
    }

    #[test]
    fn test_encode_method_patch() {
        let mut encoder = Encoder::default();
        let res = encode(&mut encoder, vec![method("PATCH")]);

        assert_eq!(res[0], 0b01000000 | 2); // Incremental indexing w/ name pulled from table
        assert_eq!(res[1], 0x80 | 5); // header value w/ huffman coding

        assert_eq!("PATCH", huff_decode(&res[2..7]));
        assert_eq!(encoder.table.len(), 1);

        let res = encode(&mut encoder, vec![method("PATCH")]);

        assert_eq!((1 << 7) | 62, res[0]);
        assert_eq!(1, res.len());
    }

    #[test]
    fn test_encode_indexed_name_literal_value() {
        let mut encoder = Encoder::default();
        let res = encode(&mut encoder, vec![header("content-language", "foo")]);

        assert_eq!(res[0], 0b01000000 | 27); // Indexed name
        assert_eq!(res[1], 0x80 | 2); // header value w/ huffman coding

        assert_eq!("foo", huff_decode(&res[2..4]));

        // Same name, new value should still use incremental
        let res = encode(&mut encoder, vec![header("content-language", "bar")]);
        assert_eq!(res[0], 0b01000000 | 27); // Indexed name
        assert_eq!(res[1], 0x80 | 3); // header value w/ huffman coding
        assert_eq!("bar", huff_decode(&res[2..5]));
    }

    #[test]
    fn test_repeated_headers_are_indexed() {
        let mut encoder = Encoder::default();
        let res = encode(&mut encoder, vec![header("foo", "hello")]);

        assert_eq!(&[0b01000000, 0x80 | 2], &res[0..2]);
        assert_eq!("foo", huff_decode(&res[2..4]));
        assert_eq!(0x80 | 4, res[4]);
        assert_eq!("hello", huff_decode(&res[5..]));
        assert_eq!(9, res.len());

        assert_eq!(1, encoder.table.len());

        let res = encode(&mut encoder, vec![header("foo", "hello")]);
        assert_eq!([0x80 | 62], *res);

        assert_eq!(encoder.table.len(), 1);
    }

    #[test]
    fn test_mixed_case_header_name_is_lowercased_on_hpack_wire() {
        let name = HeaderName::from_static("X-CuStOm");
        let mut dst = BytesMut::new();

        encode_header_name(&name, &mut dst);

        assert_eq!(0x80, dst[0] & 0x80);
        let huff_len = (dst[0] & 0x7f) as usize;
        assert_eq!("x-custom", huff_decode(&dst[1..1 + huff_len]));
    }

    #[test]
    fn test_evicting_headers() {
        let mut encoder = Encoder::default();

        // Fill the table
        for i in 0..64 {
            let key = format!("x-hello-world-{i:02}");
            let res = encode(&mut encoder, vec![header(&key, &key)]);

            assert_eq!(&[0b01000000, 0x80 | 12], &res[0..2]);
            assert_eq!(key, huff_decode(&res[2..14]));
            assert_eq!(0x80 | 12, res[14]);
            assert_eq!(key, huff_decode(&res[15..]));
            assert_eq!(27, res.len());

            // Make sure the header can be found...
            let res = encode(&mut encoder, vec![header(&key, &key)]);

            // Only check that it is found
            assert_eq!(0x80, res[0] & 0x80);
        }

        assert_eq!(4096, encoder.table.size());
        assert_eq!(64, encoder.table.len());

        // Find existing headers
        for i in 0..64 {
            let key = format!("x-hello-world-{i:02}");
            let res = encode(&mut encoder, vec![header(&key, &key)]);
            assert_eq!(0x80, res[0] & 0x80);
        }

        // Insert a new header
        let key = "x-hello-world-64";
        let res = encode(&mut encoder, vec![header(key, key)]);

        assert_eq!(&[0b01000000, 0x80 | 12], &res[0..2]);
        assert_eq!(key, huff_decode(&res[2..14]));
        assert_eq!(0x80 | 12, res[14]);
        assert_eq!(key, huff_decode(&res[15..]));
        assert_eq!(27, res.len());

        assert_eq!(64, encoder.table.len());

        // Now try encoding entries that should exist in the table
        for i in 1..65 {
            let key = format!("x-hello-world-{i:02}");
            let res = encode(&mut encoder, vec![header(&key, &key)]);
            assert_eq!(0x80 | (61 + (65 - i)), res[0]);
        }
    }

    #[test]
    fn test_large_headers_are_not_indexed() {
        let mut encoder = Encoder::new(128, 0);
        let key = "hello-world-hello-world-HELLO-zzz";

        let res = encode(&mut encoder, vec![header(key, key)]);

        assert_eq!(&[0, 0x80 | 25], &res[..2]);

        assert_eq!(0, encoder.table.len());
        assert_eq!(0, encoder.table.size());
    }

    #[test]
    fn test_sensitive_headers_are_never_indexed() {
        let name = "my-password".parse().unwrap();
        let mut value = HeaderValue::from_bytes(b"12345").unwrap();
        value.set_sensitive(true);

        let header = Header::Field {
            name: Some(name),
            value,
        };

        // Now, try to encode the sensitive header

        let mut encoder = Encoder::default();
        let res = encode(&mut encoder, vec![header]);

        assert_eq!(&[0b10000, 0x80 | 8], &res[..2]);
        assert_eq!("my-password", huff_decode(&res[2..10]));
        assert_eq!(0x80 | 4, res[10]);
        assert_eq!("12345", huff_decode(&res[11..]));

        // Now, try to encode a sensitive header w/ a name in the static table
        let name = "authorization".parse().unwrap();
        let mut value = HeaderValue::from_bytes(b"12345").unwrap();
        value.set_sensitive(true);

        let header = Header::Field {
            name: Some(name),
            value,
        };

        let mut encoder = Encoder::default();
        let res = encode(&mut encoder, vec![header]);

        assert_eq!(&[0b11111, 8], &res[..2]);
        assert_eq!(0x80 | 4, res[2]);
        assert_eq!("12345", huff_decode(&res[3..]));

        // Using the name component of a previously indexed header (without
        // sensitive flag set)

        _ = encode(
            &mut encoder,
            vec![self::header("my-password", "not-so-secret")],
        );

        let name = "my-password".parse().unwrap();
        let mut value = HeaderValue::from_bytes(b"12345").unwrap();
        value.set_sensitive(true);

        let header = Header::Field {
            name: Some(name),
            value,
        };
        let res = encode(&mut encoder, vec![header]);

        assert_eq!(&[0b11111, 47], &res[..2]);
        assert_eq!(0x80 | 4, res[2]);
        assert_eq!("12345", huff_decode(&res[3..]));
    }

    #[test]
    fn test_content_length_value_not_indexed() {
        let mut encoder = Encoder::default();
        let res = encode(&mut encoder, vec![header("content-length", "1234")]);

        assert_eq!(&[15, 13, 0x80 | 3], &res[0..3]);
        assert_eq!("1234", huff_decode(&res[3..]));
        assert_eq!(6, res.len());
    }

    #[test]
    fn chrome_policy_indexes_content_length_and_sensitive_cookie_values() {
        let mut encoder = Encoder::default();
        let mut cookie = header("cookie", "a=b");
        if let Header::Field { value, .. } = &mut cookie {
            value.set_sensitive(true);
        }
        let mut dst = BytesMut::new();
        encoder.encode_with_policy(
            vec![header("content-length", "1234"), cookie],
            &mut dst,
            true,
        );

        assert_eq!(0b0100_0000 | 28, dst[0]);
        assert_eq!(2, encoder.table.len());
    }

    #[test]
    fn chrome_policy_emits_one_h2_cookie_field_per_pair_in_place() {
        let mut encoder = Encoder::default();
        let mut cookie = header("cookie", "__kasada=nonce; __Host-ghost-continuity=nonce");
        if let Header::Field { value, .. } = &mut cookie {
            value.set_sensitive(true);
        }
        let mut dst = BytesMut::new();
        encoder.encode_with_policy(
            vec![
                header("accept-language", "en-US"),
                cookie,
                header("priority", "u=1, i"),
            ],
            &mut dst,
            true,
        );

        assert_eq!(
            decode_field_rows(dst),
            [
                ("accept-language".to_owned(), "en-US".to_owned()),
                ("cookie".to_owned(), "__kasada=nonce".to_owned()),
                (
                    "cookie".to_owned(),
                    "__Host-ghost-continuity=nonce".to_owned(),
                ),
                ("priority".to_owned(), "u=1, i".to_owned()),
            ]
        );
        assert_eq!(encoder.table.len(), 4);

        let mut second_block = BytesMut::new();
        let mut repeated = header("cookie", "__kasada=nonce; __Host-ghost-continuity=nonce");
        if let Header::Field { value, .. } = &mut repeated {
            value.set_sensitive(true);
        }
        encoder.encode_with_policy(vec![repeated], &mut second_block, true);
        assert_eq!(second_block.len(), 2);
        assert!(second_block.iter().all(|byte| byte & 0x80 == 0x80));
    }

    #[test]
    fn default_hpack_policy_leaves_a_combined_cookie_unchanged() {
        let mut encoder = Encoder::default();
        let mut dst = BytesMut::new();
        encoder.encode(vec![header("cookie", "first=1; second=2")], &mut dst);

        assert_eq!(
            decode_field_rows(dst),
            [("cookie".to_owned(), "first=1; second=2".to_owned())]
        );
    }

    #[test]
    fn chrome_cookie_crumbs_preserve_sensitivity_and_reject_ambiguity() {
        let mut cookie = header("cookie", "first=1; second=2");
        if let Header::Field { value, .. } = &mut cookie {
            value.set_sensitive(true);
        }
        let crumbs = chrome_cookie_crumbs(&cookie).unwrap();
        assert_eq!(crumbs.len(), 2);
        assert!(crumbs.iter().all(|crumb| match crumb {
            Header::Field { value, .. } => value.is_sensitive(),
            _ => false,
        }));

        for malformed in [
            "first=1;",
            "first=1; missing-value",
            "=missing-name; b=2",
            "first=\"legacy;value\"; second=2",
        ] {
            assert!(chrome_cookie_crumbs(&header("cookie", malformed)).is_none());
        }
    }

    #[test]
    fn test_encoding_headers_with_same_name() {
        let mut encoder = Encoder::default();
        let name = "hello";

        // Encode first one
        _ = encode(&mut encoder, vec![header(name, "one")]);

        // Encode second one
        let res = encode(&mut encoder, vec![header(name, "two")]);
        assert_eq!(&[0x40 | 62, 0x80 | 3], &res[0..2]);
        assert_eq!("two", huff_decode(&res[2..]));
        assert_eq!(5, res.len());

        // Encode the first one again
        let res = encode(&mut encoder, vec![header(name, "one")]);
        assert_eq!(&[0x80 | 63], &res[..]);

        // Now the second one
        let res = encode(&mut encoder, vec![header(name, "two")]);
        assert_eq!(&[0x80 | 62], &res[..]);
    }

    #[test]
    fn test_evicting_headers_when_multiple_of_same_name_are_in_table() {
        // The encoder only has space for 2 headers
        let mut encoder = Encoder::new(76, 0);

        _ = encode(&mut encoder, vec![header("foo", "bar")]);
        assert_eq!(1, encoder.table.len());

        _ = encode(&mut encoder, vec![header("bar", "foo")]);
        assert_eq!(2, encoder.table.len());

        // This will evict the first header, while still referencing the header
        // name
        let res = encode(&mut encoder, vec![header("foo", "baz")]);
        assert_eq!(&[0x40 | 63, 0, 0x80 | 3], &res[..3]);
        assert_eq!(2, encoder.table.len());

        // Try adding the same header again
        let res = encode(&mut encoder, vec![header("foo", "baz")]);
        assert_eq!(&[0x80 | 62], &res[..]);
        assert_eq!(2, encoder.table.len());
    }

    #[test]
    fn test_max_size_zero() {
        // Static table only
        let mut encoder = Encoder::new(0, 0);
        let res = encode(&mut encoder, vec![method("GET")]);
        assert_eq!(*res, [0x80 | 2]);
        assert_eq!(encoder.table.len(), 0);

        let res = encode(&mut encoder, vec![header("foo", "bar")]);
        assert_eq!(&[0, 0x80 | 2], &res[..2]);
        assert_eq!("foo", huff_decode(&res[2..4]));
        assert_eq!(0x80 | 3, res[4]);
        assert_eq!("bar", huff_decode(&res[5..8]));
        assert_eq!(0, encoder.table.len());

        // Encode a custom value
        let res = encode(&mut encoder, vec![header("transfer-encoding", "chunked")]);
        assert_eq!(&[15, 42, 0x80 | 6], &res[..3]);
        assert_eq!("chunked", huff_decode(&res[3..]));
    }

    #[test]
    fn test_update_max_size_combos() {
        let mut encoder = Encoder::default();
        assert!(encoder.size_update.is_none());
        assert_eq!(4096, encoder.table.max_size());

        encoder.update_max_size(4096); // Default size
        assert!(encoder.size_update.is_none());

        encoder.update_max_size(0);
        assert_eq!(Some(SizeUpdate::One(0)), encoder.size_update);

        encoder.update_max_size(100);
        assert_eq!(Some(SizeUpdate::Two(0, 100)), encoder.size_update);

        let mut encoder = Encoder::default();
        encoder.update_max_size(8000);
        assert_eq!(Some(SizeUpdate::One(8000)), encoder.size_update);

        encoder.update_max_size(100);
        assert_eq!(Some(SizeUpdate::One(100)), encoder.size_update);

        encoder.update_max_size(8000);
        assert_eq!(Some(SizeUpdate::Two(100, 8000)), encoder.size_update);

        encoder.update_max_size(4000);
        assert_eq!(Some(SizeUpdate::Two(100, 4000)), encoder.size_update);

        encoder.update_max_size(50);
        assert_eq!(Some(SizeUpdate::One(50)), encoder.size_update);
    }

    #[test]
    fn test_resizing_table() {
        let mut encoder = Encoder::default();

        // Add a header
        _ = encode(&mut encoder, vec![header("foo", "bar")]);

        encoder.update_max_size(1);
        assert_eq!(1, encoder.table.len());

        let res = encode(&mut encoder, vec![method("GET")]);
        assert_eq!(&[32 | 1, 0x80 | 2], &res[..]);
        assert_eq!(0, encoder.table.len());

        let res = encode(&mut encoder, vec![header("foo", "bar")]);
        assert_eq!(0, res[0]);

        encoder.update_max_size(100);
        let res = encode(&mut encoder, vec![header("foo", "bar")]);
        assert_eq!(&[32 | 31, 69, 64], &res[..3]);

        encoder.update_max_size(0);
        let res = encode(&mut encoder, vec![header("foo", "bar")]);
        assert_eq!(&[32, 0], &res[..2]);
    }

    #[test]
    fn test_decreasing_table_size_without_eviction() {
        let mut encoder = Encoder::default();

        // Add a header
        _ = encode(&mut encoder, vec![header("foo", "bar")]);

        encoder.update_max_size(100);
        assert_eq!(1, encoder.table.len());

        let res = encode(&mut encoder, vec![header("foo", "bar")]);
        assert_eq!(&[32 | 31, 69, 0x80 | 62], &res[..]);
    }

    #[test]
    fn test_nameless_header() {
        let mut encoder = Encoder::default();

        let res = encode(
            &mut encoder,
            vec![
                Header::Field {
                    name: Some("hello".parse().unwrap()),
                    value: HeaderValue::from_bytes(b"world").unwrap(),
                },
                Header::Field {
                    name: None,
                    value: HeaderValue::from_bytes(b"zomg").unwrap(),
                },
            ],
        );

        assert_eq!(&[0x40, 0x80 | 4], &res[0..2]);
        assert_eq!("hello", huff_decode(&res[2..6]));
        assert_eq!(0x80 | 4, res[6]);
        assert_eq!("world", huff_decode(&res[7..11]));

        // Next is not indexed
        assert_eq!(&[15, 47, 0x80 | 3], &res[11..14]);
        assert_eq!("zomg", huff_decode(&res[14..]));
    }

    #[test]
    fn test_large_size_update() {
        let mut encoder = Encoder::default();

        encoder.update_max_size(1912930560);
        assert_eq!(Some(SizeUpdate::One(1912930560)), encoder.size_update);

        let mut dst = BytesMut::with_capacity(6);
        encoder.encode_size_updates(&mut dst);
        assert_eq!([63, 225, 129, 148, 144, 7], &dst[..]);
    }

    #[test]
    #[ignore]
    fn test_evicted_overflow() {
        // Not sure what the best way to do this is.
    }

    fn encode(e: &mut Encoder, hdrs: Vec<Header<Option<HeaderName>>>) -> BytesMut {
        let mut dst = BytesMut::with_capacity(1024);
        e.encode(hdrs, &mut dst);
        dst
    }

    fn method(s: &str) -> Header<Option<HeaderName>> {
        Header::Method(Method::from_bytes(s.as_bytes()).unwrap())
    }

    fn header(name: &str, val: &str) -> Header<Option<HeaderName>> {
        let name = HeaderName::from_bytes(name.as_bytes()).unwrap();
        let value = HeaderValue::from_bytes(val.as_bytes()).unwrap();

        Header::Field {
            name: Some(name),
            value,
        }
    }

    fn decode_field_rows(mut encoded: BytesMut) -> Vec<(String, String)> {
        let mut decoder = Decoder::new(4096);
        let mut rows = Vec::new();
        decoder
            .decode(&mut Cursor::new(&mut encoded), |header| {
                if let Header::Field { name, value } = header {
                    rows.push((name.as_str().to_owned(), value.to_str().unwrap().to_owned()));
                }
                ControlFlow::Continue(())
            })
            .unwrap();
        rows
    }

    fn huff_decode(src: &[u8]) -> BytesMut {
        let mut buf = BytesMut::new();
        huffman::decode(src, &mut buf).unwrap()
    }
}
