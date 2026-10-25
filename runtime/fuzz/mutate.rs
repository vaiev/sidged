// Copyright 2026 VAIEV
// SPDX-License-Identifier: Apache-2.0
//! Deterministic mutation fuzzing shared by the runtime and companion crates' tests
//! (`#[path = ".../runtime/fuzz/mutate.rs"] mod mutate;`). No dependency beyond serde_json.
//!
//! A case starts from a shared vector, applies one to three tree mutations (a value replaced,
//! a member dropped, an element duplicated, a node wrapped in an array) and runs the target
//! under `catch_unwind` with a time limit. The case count is fixed per test and raised with
//! `VAIKOR_FUZZ_ITERS`; the seed is fixed, so every failure reproduces.
#![allow(dead_code)]

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::time::{Duration, Instant};

use serde_json::{json, Map, Value};

pub struct Rng(pub u64);

impl Rng {
    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    pub fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
    pub fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }
}

/// Strings that sit on parser edges: money, versions, classes, CEL, Unicode (NUL, a combining
/// accent that is not NFC, bidi override, astral plane), dates, keys and time words.
pub const STRINGS: &[&str] = &[
    "",
    "0",
    "0.0",
    "1x",
    "-1",
    "1e3",
    "NaN",
    ".5",
    "5.",
    "00.10",
    "999999999999999999999999",
    "CHF",
    "chf",
    "EUR",
    "CH",
    "EU",
    "egress",
    "read",
    "write",
    "secrets",
    "health.records",
    "free",
    "metered",
    "call",
    "expr",
    "map",
    "0.1",
    "0.2",
    "4.0",
    "dcbor",
    "EdDSA",
    "delete",
    "tag:vaikor.com,2026:capability:message.send",
    "free.slots",
    "free.filter(x, x > 0)",
    "a.b.c(",
    "[1, 2]",
    "((((((((((1))))))))))",
    "size(free) > 1 && true",
    "\u{0}",
    "é",
    "e\u{301}",
    "\u{202e}",
    "🙂",
    "2026-10-15T08:00:00Z",
    "2026-02-30T25:61:00Z",
    "1970-01-01T00:00:00Z",
    "did:key:z6Mkfuzz",
    "did:key:",
    "rfc8032-test-1",
    "en",
    "de",
    "gsw",
    "null",
    "true",
    "morn am füfi",
    "halb 8",
    "in 10 Minuten",
    "am Mäntigmorge",
    "viertel vor 25",
    "8.30",
    "12:99",
    "PT10M",
    "P1D",
    "inere haube Stund",
    "\n",
    "\t",
    "<script>",
    "%00",
    "../..",
];

pub const KEYS: &[&str] = &[
    "lit", "ref", "item", "max", "amount", "currency", "class", "id", "v", "kind", "type",
    "content", "sig", "value", "tags", "until", "intent", "slots", "lang", "props", "children",
    "text", "steps", "approval",
];

pub fn random_value(rng: &mut Rng, depth: usize) -> Value {
    match rng.below(if depth > 3 { 5 } else { 8 }) {
        0 => Value::Null,
        1 => json!(rng.below(2) == 0),
        2 => json!(rng.next() as i64),
        3 => json!(rng.below(40) as u64),
        4 => json!(rng.pick(STRINGS)),
        5 => Value::Array(
            (0..rng.below(4))
                .map(|_| random_value(rng, depth + 1))
                .collect(),
        ),
        6 => {
            let mut map = Map::new();
            for _ in 0..rng.below(3) {
                map.insert((*rng.pick(KEYS)).into(), random_value(rng, depth + 1));
            }
            Value::Object(map)
        }
        _ => json!(rng.pick(STRINGS).repeat(1 + rng.below(64))),
    }
}

/// Every node, so a mutation can pick one uniformly.
fn size(value: &Value) -> usize {
    1 + match value {
        Value::Array(items) => items.iter().map(size).sum(),
        Value::Object(map) => map.values().map(size).sum(),
        _ => 0,
    }
}

fn mutate_at(value: &mut Value, mut target: usize, rng: &mut Rng) -> usize {
    if target == 0 {
        match rng.below(4) {
            0 => *value = random_value(rng, 0),
            1 => {
                if let Value::Object(map) = value {
                    if let Some(key) = map.keys().nth(rng.below(map.len())).cloned() {
                        map.remove(&key);
                    }
                }
            }
            2 => {
                if let Value::Array(items) = value {
                    if !items.is_empty() {
                        let copy = items[rng.below(items.len())].clone();
                        items.push(copy);
                    }
                }
            }
            _ => *value = json!([value.clone()]),
        }
        return usize::MAX;
    }
    target -= 1;
    let children: Vec<&mut Value> = match value {
        Value::Array(items) => items.iter_mut().collect(),
        Value::Object(map) => map.values_mut().collect(),
        _ => return target,
    };
    for child in children {
        let n = size(child);
        if target < n {
            mutate_at(child, target, rng);
            return usize::MAX;
        }
        target -= n;
    }
    target
}

pub fn mutate(value: &mut Value, rng: &mut Rng) {
    for _ in 0..1 + rng.below(3) {
        let target = rng.below(size(value));
        mutate_at(value, target, rng);
    }
}

/// Byte-level mutation: flip, insert, delete, truncate or duplicate a slice.
pub fn mutate_bytes(bytes: &mut Vec<u8>, rng: &mut Rng) {
    for _ in 0..1 + rng.below(3) {
        let len = bytes.len();
        match rng.below(5) {
            0 if len > 0 => {
                let at = rng.below(len);
                bytes[at] ^= 1 << rng.below(8);
            }
            1 => {
                let at = rng.below(len + 1);
                bytes.insert(at, rng.next() as u8);
            }
            2 if len > 0 => {
                bytes.remove(rng.below(len));
            }
            3 => bytes.truncate(rng.below(len + 1)),
            _ if len > 0 => {
                let start = rng.below(len);
                let end = (start + 1 + rng.below(8)).min(len);
                let slice = bytes[start..end].to_vec();
                let at = rng.below(bytes.len() + 1);
                bytes.splice(at..at, slice);
            }
            _ => bytes.push(rng.next() as u8),
        }
    }
}

/// Text-level mutation for utterance-like inputs: splice in words of `STRINGS`, drop or
/// repeat a character, insert a random code point.
pub fn mutate_text(text: &str, rng: &mut Rng) -> String {
    let mut chars: Vec<char> = text.chars().collect();
    for _ in 0..1 + rng.below(3) {
        let len = chars.len();
        match rng.below(4) {
            0 => {
                let at = rng.below(len + 1);
                let word: Vec<char> = format!(" {} ", rng.pick(STRINGS)).chars().collect();
                chars.splice(at..at, word);
            }
            1 if len > 0 => {
                chars.remove(rng.below(len));
            }
            2 if len > 0 => {
                let at = rng.below(len);
                let repeated = vec![chars[at]; 1 + rng.below(16)];
                chars.splice(at..at, repeated);
            }
            _ => {
                let at = rng.below(len + 1);
                let c = char::from_u32(rng.next() as u32 % 0x11_0000).unwrap_or('\u{fffd}');
                chars.insert(at, c);
            }
        }
    }
    chars.into_iter().collect()
}

pub fn iterations(default: usize) -> usize {
    std::env::var("VAIKOR_FUZZ_ITERS")
        .ok()
        .and_then(|n| n.parse().ok())
        .unwrap_or(default)
}

/// Run `target` on `cases` inputs; each must return within `limit` and never panic.
pub fn run<T: std::fmt::Debug>(
    cases: usize,
    limit: Duration,
    mut make: impl FnMut(usize, &mut Rng) -> T,
    target: impl Fn(&T),
) {
    let mut rng = Rng(0x5eed_0000_0000_0001);
    for case in 0..cases {
        let input = make(case, &mut rng);
        let started = Instant::now();
        let outcome = catch_unwind(AssertUnwindSafe(|| target(&input)));
        assert!(outcome.is_ok(), "case {case} panicked: {input:?}");
        let took = started.elapsed();
        assert!(took < limit, "case {case} took {took:?}: {input:?}");
    }
}
