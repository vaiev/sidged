// Copyright 2026 VAIEV
// SPDX-License-Identifier: Apache-2.0
//! A streaming reader for the metadata header of a GGUF file (0017 L3b).
//!
//! It reads the magic, the version (2 or 3), the tensor and key-value counts and then the
//! typed key-value pairs, skipping every value it is not asked for without loading it, and
//! returns the value of one string key. The tensor infos and the weights are never read.
//! Malformed or implausible headers are refused with explicit limits.

use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

use crate::linguist::LinguistOutput;

/// The metadata key by which a linguist GGUF declares the output form it was trained on.
pub const OUTPUT_KEY: &str = "sidged.linguist.output";

/// Limits well above any real model (a 262 144-token vocabulary has a header of about 10 MB).
const MAX_HEADER: u64 = 64 << 20;
const MAX_TENSORS: u64 = 1 << 20;
const MAX_PAIRS: u64 = 1 << 16;
const MAX_KEY: u64 = 65_535;
const MAX_STRING: u64 = 16 << 20;
const MAX_ARRAY_ELEMENTS: u64 = 1 << 20;

/// The output form `path` declares in `sidged.linguist.output` (0017 L3b): absent means full;
/// any value other than `"compact"` or `"full"`, or a non-string value, is refused.
pub fn linguist_output(path: &Path) -> Result<LinguistOutput, String> {
    let file = File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let value = string_value(BufReader::new(file), OUTPUT_KEY)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    match value.as_deref() {
        None | Some("full") => Ok(LinguistOutput::Full),
        Some("compact") => Ok(LinguistOutput::Compact),
        Some(other) => Err(format!(
            "{}: {OUTPUT_KEY} must be \"compact\" or \"full\", got {other:?}",
            path.display()
        )),
    }
}

/// The value of the string metadata key `key` in the GGUF read from `reader`, or `None` when
/// the header has no such key. A header that is malformed, of a version other than 2 or 3,
/// beyond the limits, or that has `key` twice or with a non-string type, is refused.
pub fn string_value<R: Read>(reader: R, key: &str) -> Result<Option<String>, String> {
    let mut header = Header { reader, read: 0 };
    let mut magic = [0u8; 4];
    header.exact(&mut magic)?;
    if &magic != b"GGUF" {
        return Err("not a GGUF file (bad magic)".into());
    }
    let version = header.u32()?;
    if version != 2 && version != 3 {
        return Err(format!("unsupported GGUF version {version}"));
    }
    let tensors = header.u64()?;
    if tensors > MAX_TENSORS {
        return Err(format!("implausible tensor count {tensors}"));
    }
    let pairs = header.u64()?;
    if pairs > MAX_PAIRS {
        return Err(format!("implausible key-value count {pairs}"));
    }
    let mut found = None;
    for _ in 0..pairs {
        let len = header.u64()?;
        if len > MAX_KEY {
            return Err(format!("implausible key length {len}"));
        }
        let name = header.text(len)?;
        let kind = header.u32()?;
        if name != key {
            header.skip_value(kind)?;
            continue;
        }
        if found.is_some() {
            return Err(format!("key {key} appears twice"));
        }
        if kind != STRING {
            return Err(format!("key {key} is not a string (type {kind})"));
        }
        found = Some(header.string()?);
    }
    Ok(found)
}

const STRING: u32 = 8;
const ARRAY: u32 = 9;

/// The size of a fixed-size value type, `None` for string and array.
fn scalar_size(kind: u32) -> Result<Option<u64>, String> {
    Ok(Some(match kind {
        0 | 1 | 7 => 1, // uint8, int8, bool
        2 | 3 => 2,     // uint16, int16
        4..=6 => 4,     // uint32, int32, float32
        10..=12 => 8,   // uint64, int64, float64
        STRING | ARRAY => return Ok(None),
        other => return Err(format!("unknown value type {other}")),
    }))
}

/// The reader with a count of the header bytes read so far, bounded by `MAX_HEADER`.
struct Header<R> {
    reader: R,
    read: u64,
}

impl<R: Read> Header<R> {
    fn take(&mut self, len: u64) -> Result<(), String> {
        self.read = self.read.saturating_add(len);
        if self.read > MAX_HEADER {
            return Err(format!("header larger than {MAX_HEADER} bytes"));
        }
        Ok(())
    }

    fn exact(&mut self, buf: &mut [u8]) -> Result<(), String> {
        self.take(buf.len() as u64)?;
        self.reader
            .read_exact(buf)
            .map_err(|e| format!("truncated GGUF header: {e}"))
    }

    fn u32(&mut self) -> Result<u32, String> {
        let mut buf = [0u8; 4];
        self.exact(&mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    fn u64(&mut self) -> Result<u64, String> {
        let mut buf = [0u8; 8];
        self.exact(&mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }

    fn text(&mut self, len: u64) -> Result<String, String> {
        // len is at most MAX_STRING, checked by the caller.
        let mut buf = vec![0u8; len as usize];
        self.exact(&mut buf)?;
        String::from_utf8(buf).map_err(|_| "a GGUF string is not UTF-8".to_string())
    }

    fn string_len(&mut self) -> Result<u64, String> {
        let len = self.u64()?;
        if len > MAX_STRING {
            return Err(format!("implausible string length {len}"));
        }
        Ok(len)
    }

    fn string(&mut self) -> Result<String, String> {
        let len = self.string_len()?;
        self.text(len)
    }

    /// Skip `len` bytes without keeping them.
    fn skip(&mut self, len: u64) -> Result<(), String> {
        self.take(len)?;
        let copied = std::io::copy(&mut (&mut self.reader).take(len), &mut std::io::sink())
            .map_err(|e| format!("GGUF header: {e}"))?;
        if copied != len {
            return Err("truncated GGUF header".into());
        }
        Ok(())
    }

    fn skip_value(&mut self, kind: u32) -> Result<(), String> {
        if let Some(size) = scalar_size(kind)? {
            return self.skip(size);
        }
        if kind == STRING {
            let len = self.string_len()?;
            return self.skip(len);
        }
        let elem = self.u32()?;
        let count = self.u64()?;
        if count > MAX_ARRAY_ELEMENTS {
            return Err(format!("implausible array length {count}"));
        }
        match scalar_size(elem)? {
            // count * size is at most 2^23: no overflow.
            Some(size) => self.skip(count * size),
            None if elem == STRING => {
                for _ in 0..count {
                    let len = self.string_len()?;
                    self.skip(len)?;
                }
                Ok(())
            }
            None => Err("nested arrays are not a supported value type".into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn string(out: &mut Vec<u8>, text: &str) {
        out.extend((text.len() as u64).to_le_bytes());
        out.extend(text.as_bytes());
    }

    /// A header-only GGUF: magic, version, tensor count 0, the pairs as written by `pairs`.
    fn header(version: u32, kv_count: u64, pairs: &[u8]) -> Vec<u8> {
        let mut out = b"GGUF".to_vec();
        out.extend(version.to_le_bytes());
        out.extend(0u64.to_le_bytes());
        out.extend(kv_count.to_le_bytes());
        out.extend(pairs);
        out
    }

    /// Pairs like a real linguist GGUF: scalars, an array of strings, an array of floats,
    /// then `sidged.linguist.output` with `value` (if any), then a trailing scalar.
    fn typical_pairs(value: Option<&str>) -> (u64, Vec<u8>) {
        let mut pairs = Vec::new();
        string(&mut pairs, "general.architecture");
        pairs.extend(STRING.to_le_bytes());
        string(&mut pairs, "qwen3");
        string(&mut pairs, "general.alignment");
        pairs.extend(4u32.to_le_bytes()); // uint32
        pairs.extend(32u32.to_le_bytes());
        string(&mut pairs, "general.flag");
        pairs.extend(7u32.to_le_bytes()); // bool
        pairs.push(1);
        string(&mut pairs, "tokenizer.ggml.tokens");
        pairs.extend(ARRAY.to_le_bytes());
        pairs.extend(STRING.to_le_bytes());
        pairs.extend(3u64.to_le_bytes());
        for token in ["a", "sidged.linguist.output", "compact"] {
            string(&mut pairs, token);
        }
        string(&mut pairs, "tokenizer.ggml.scores");
        pairs.extend(ARRAY.to_le_bytes());
        pairs.extend(6u32.to_le_bytes()); // float32
        pairs.extend(2u64.to_le_bytes());
        pairs.extend(1.5f32.to_le_bytes());
        pairs.extend((-2.0f32).to_le_bytes());
        let mut count = 5;
        if let Some(value) = value {
            string(&mut pairs, OUTPUT_KEY);
            pairs.extend(STRING.to_le_bytes());
            string(&mut pairs, value);
            count += 1;
        }
        string(&mut pairs, "general.file_type");
        pairs.extend(12u32.to_le_bytes()); // float64
        pairs.extend(7.0f64.to_le_bytes());
        (count + 1, pairs)
    }

    fn typical(value: Option<&str>) -> Vec<u8> {
        let (count, pairs) = typical_pairs(value);
        header(3, count, &pairs)
    }

    #[test]
    fn a_declared_value_is_returned_and_other_values_are_skipped() {
        let file = typical(Some("compact"));
        assert_eq!(
            string_value(file.as_slice(), OUTPUT_KEY)
                .unwrap()
                .as_deref(),
            Some("compact")
        );
        assert_eq!(
            string_value(file.as_slice(), "general.architecture")
                .unwrap()
                .as_deref(),
            Some("qwen3")
        );
        // Version 2 has the same layout.
        let (count, pairs) = typical_pairs(Some("full"));
        let v2 = header(2, count, &pairs);
        assert_eq!(
            string_value(v2.as_slice(), OUTPUT_KEY).unwrap().as_deref(),
            Some("full")
        );
        // Tensor infos and weights after the pairs are never read.
        let mut with_tail = file.clone();
        with_tail.extend([0xff; 64]);
        assert_eq!(
            string_value(with_tail.as_slice(), OUTPUT_KEY)
                .unwrap()
                .as_deref(),
            Some("compact")
        );
    }

    #[test]
    fn an_absent_key_is_none_even_when_an_array_holds_its_name() {
        let file = typical(None);
        assert_eq!(string_value(file.as_slice(), OUTPUT_KEY).unwrap(), None);
        let empty = header(3, 0, &[]);
        assert_eq!(string_value(empty.as_slice(), OUTPUT_KEY).unwrap(), None);
    }

    #[test]
    fn a_non_string_or_repeated_key_is_refused() {
        let mut pairs = Vec::new();
        string(&mut pairs, OUTPUT_KEY);
        pairs.extend(4u32.to_le_bytes());
        pairs.extend(1u32.to_le_bytes());
        let file = header(3, 1, &pairs);
        assert!(string_value(file.as_slice(), OUTPUT_KEY)
            .unwrap_err()
            .contains("not a string"));
        // An array of strings is not a string either.
        let mut pairs = Vec::new();
        string(&mut pairs, OUTPUT_KEY);
        pairs.extend(ARRAY.to_le_bytes());
        pairs.extend(STRING.to_le_bytes());
        pairs.extend(1u64.to_le_bytes());
        string(&mut pairs, "compact");
        let file = header(3, 1, &pairs);
        assert!(string_value(file.as_slice(), OUTPUT_KEY)
            .unwrap_err()
            .contains("not a string"));
        let mut pairs = Vec::new();
        for value in ["full", "compact"] {
            string(&mut pairs, OUTPUT_KEY);
            pairs.extend(STRING.to_le_bytes());
            string(&mut pairs, value);
        }
        let file = header(3, 2, &pairs);
        assert!(string_value(file.as_slice(), OUTPUT_KEY)
            .unwrap_err()
            .contains("twice"));
    }

    #[test]
    fn bad_magic_and_unsupported_versions_are_refused() {
        let mut file = typical(Some("compact"));
        file[0] = b'g';
        assert!(string_value(file.as_slice(), OUTPUT_KEY)
            .unwrap_err()
            .contains("magic"));
        for version in [1u32, 4, 0x0300_0000] {
            let (count, pairs) = typical_pairs(Some("compact"));
            let file = header(version, count, &pairs);
            assert!(
                string_value(file.as_slice(), OUTPUT_KEY)
                    .unwrap_err()
                    .contains("version"),
                "version {version}"
            );
        }
    }

    #[test]
    fn a_truncated_header_is_refused_at_every_length() {
        let file = typical(Some("compact"));
        for len in 0..file.len() {
            assert!(
                string_value(&file[..len], OUTPUT_KEY).is_err(),
                "accepted {len} of {} bytes",
                file.len()
            );
        }
    }

    #[test]
    fn implausible_counts_and_lengths_are_refused() {
        // Counts.
        let mut file = header(3, 1, &[]);
        file[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(string_value(file.as_slice(), OUTPUT_KEY)
            .unwrap_err()
            .contains("tensor count"));
        let file = header(3, u64::MAX, &[]);
        assert!(string_value(file.as_slice(), OUTPUT_KEY)
            .unwrap_err()
            .contains("key-value count"));
        // A key longer than the limit.
        let mut pairs = Vec::new();
        pairs.extend(u64::MAX.to_le_bytes());
        let file = header(3, 1, &pairs);
        assert!(string_value(file.as_slice(), OUTPUT_KEY)
            .unwrap_err()
            .contains("key length"));
        // A string value longer than the limit.
        let mut pairs = Vec::new();
        string(&mut pairs, "general.name");
        pairs.extend(STRING.to_le_bytes());
        pairs.extend((1u64 << 40).to_le_bytes());
        let file = header(3, 1, &pairs);
        assert!(string_value(file.as_slice(), OUTPUT_KEY)
            .unwrap_err()
            .contains("string length"));
        // An array with more elements than the limit, of fixed-size and of string type.
        for elem in [0u32, STRING, 12] {
            let mut pairs = Vec::new();
            string(&mut pairs, "tokenizer.ggml.tokens");
            pairs.extend(ARRAY.to_le_bytes());
            pairs.extend(elem.to_le_bytes());
            pairs.extend(u64::MAX.to_le_bytes());
            let file = header(3, 1, &pairs);
            assert!(
                string_value(file.as_slice(), OUTPUT_KEY)
                    .unwrap_err()
                    .contains("array length"),
                "element type {elem}"
            );
        }
        // Unknown value types and nested arrays.
        for (outer, inner) in [(13u32, None), (u32::MAX, None), (ARRAY, Some(ARRAY))] {
            let mut pairs = Vec::new();
            string(&mut pairs, "general.x");
            pairs.extend(outer.to_le_bytes());
            if let Some(inner) = inner {
                pairs.extend(inner.to_le_bytes());
                pairs.extend(0u64.to_le_bytes());
            }
            let file = header(3, 1, &pairs);
            assert!(
                string_value(file.as_slice(), OUTPUT_KEY)
                    .unwrap_err()
                    .contains("type"),
                "type {outer}"
            );
        }
        // A key that is not UTF-8.
        let mut pairs = Vec::new();
        pairs.extend(2u64.to_le_bytes());
        pairs.extend([0xc3, 0x28]);
        pairs.extend(STRING.to_le_bytes());
        string(&mut pairs, "x");
        let file = header(3, 1, &pairs);
        assert!(string_value(file.as_slice(), OUTPUT_KEY)
            .unwrap_err()
            .contains("UTF-8"));
    }

    #[test]
    fn the_header_as_a_whole_is_bounded() {
        // Many arrays each within the per-array limit add up beyond the header limit; the
        // reader refuses once it has read MAX_HEADER bytes, not at the end of the input.
        let mut pairs = Vec::new();
        let per = MAX_ARRAY_ELEMENTS;
        let count = (MAX_HEADER / per) + 1;
        for i in 0..count {
            string(&mut pairs, &format!("x.{i}"));
            pairs.extend(ARRAY.to_le_bytes());
            pairs.extend(0u32.to_le_bytes());
            pairs.extend(per.to_le_bytes());
            pairs.resize(pairs.len() + per as usize, 0);
        }
        let file = header(3, count, &pairs);
        assert!(string_value(file.as_slice(), OUTPUT_KEY)
            .unwrap_err()
            .contains("header larger than"));
    }

    #[test]
    fn the_output_form_follows_the_key() {
        // Approval tests set the process umask to 0117 while binding; files made meanwhile
        // would be unreadable directories.
        let _umask = crate::approval::UMASK_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("sidged-gguf-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("linguist.gguf");
        std::fs::write(&path, typical(Some("compact"))).unwrap();
        assert_eq!(linguist_output(&path).unwrap(), LinguistOutput::Compact);
        std::fs::write(&path, typical(Some("full"))).unwrap();
        assert_eq!(linguist_output(&path).unwrap(), LinguistOutput::Full);
        std::fs::write(&path, typical(None)).unwrap();
        assert_eq!(linguist_output(&path).unwrap(), LinguistOutput::Full);
        for bad in ["Compact", "", "compact ", "v0.2"] {
            std::fs::write(&path, typical(Some(bad))).unwrap();
            assert!(
                linguist_output(&path).unwrap_err().contains(OUTPUT_KEY),
                "{bad:?}"
            );
        }
        std::fs::write(&path, b"not a gguf").unwrap();
        assert!(linguist_output(&path).is_err());
        assert!(linguist_output(&dir.join("missing.gguf")).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
