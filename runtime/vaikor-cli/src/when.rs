// Copyright 2026 VAIEV
// SPDX-License-Identifier: Apache-2.0
//! Resolving a time slot as the owner said it ("morn am füfi", "in 20 minutes",
//! "am Mäntigmorge", "halbi nüni") to an absolute instant in the node's time zone
//! (WP 13b). Word forms come from `assets/time-lexicon.json`; durations from the
//! duration lexicon. The model only copies the words; the Core computes the time,
//! and anything the lexicon does not cover is refused rather than guessed.
//!
//! Without a part of the day or am/pm, an hour from 1 to 6 means the afternoon
//! ("am füfi" is 17:00) and an hour from 7 to 11 the next of morning or evening
//! ("hüt am nüni" said at 19:30 is 21:00). A time that has passed moves to the next
//! day (or week, for a weekday) unless a day was named, in which case it is refused.

use std::collections::HashMap;
use std::sync::OnceLock;

use chrono::{DateTime, Datelike, Duration, NaiveDate, NaiveTime, TimeZone, Utc};
use chrono_tz::Tz;
use serde_json::Value;

/// Word forms of times (`assets/time-lexicon.json`).
pub const TIME_LEXICON_JSON: &str = include_str!("../assets/time-lexicon.json");

#[derive(Clone, Copy, Debug, PartialEq)]
enum Word {
    Day(i64),
    TomorrowOrMorning,
    Weekday(u32),
    Part(u32),
    Hour(u32),
    Half,
    HalfPast,
    Quarter,
    Past,
    To,
    ClockSuffix,
    Filler,
}

struct Lexicon {
    words: HashMap<String, Word>,
    relative: Vec<String>,
    relative_one: Vec<String>,
    am: Vec<String>,
    pm: Vec<String>,
    weekday_forms: Vec<(String, u32)>,
    part_forms: Vec<(String, u32)>,
}

fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .expect("time lexicon list")
        .iter()
        .map(|v| v.as_str().expect("time lexicon form").to_string())
        .collect()
}

fn lexicon() -> &'static Lexicon {
    static LEXICON: OnceLock<Lexicon> = OnceLock::new();
    LEXICON.get_or_init(|| {
        let doc: Value = serde_json::from_str(TIME_LEXICON_JSON).expect("time lexicon");
        let mut words = HashMap::new();
        let mut weekday_forms = Vec::new();
        let mut part_forms = Vec::new();
        let keyed = |section: &str| -> Vec<(u32, Vec<String>)> {
            doc[section]
                .as_object()
                .expect("time lexicon section")
                .iter()
                .map(|(k, v)| (k.parse().expect("time lexicon key"), strings(v)))
                .collect()
        };
        for (n, forms) in keyed("days") {
            for f in forms {
                words.insert(f, Word::Day(i64::from(n)));
            }
        }
        for (n, forms) in keyed("weekdays") {
            for f in forms {
                weekday_forms.push((f.clone(), n));
                words.insert(f, Word::Weekday(n));
            }
        }
        for (n, forms) in keyed("hours") {
            for f in forms {
                words.insert(f, Word::Hour(n));
            }
        }
        for part in doc["parts"]
            .as_object()
            .expect("time lexicon parts")
            .values()
        {
            let hour = part["hour"].as_u64().expect("part hour") as u32;
            for f in strings(&part["forms"]) {
                part_forms.push((f.clone(), hour));
                words.insert(f, Word::Part(hour));
            }
        }
        let plain: [(&str, Word); 8] = [
            ("tomorrow_or_morning", Word::TomorrowOrMorning),
            ("half", Word::Half),
            ("half_past", Word::HalfPast),
            ("quarter", Word::Quarter),
            ("past", Word::Past),
            ("to", Word::To),
            ("clock_suffix", Word::ClockSuffix),
            ("fillers", Word::Filler),
        ];
        for (section, word) in plain {
            for f in strings(&doc[section]) {
                words.entry(f).or_insert(word);
            }
        }
        // "morge" also opens weekday compounds ("Mäntigmorge").
        for f in strings(&doc["tomorrow_or_morning"]) {
            part_forms.push((f, 9));
        }
        Lexicon {
            words,
            relative: strings(&doc["relative"]["in"]),
            relative_one: strings(&doc["relative"]["in_one"]),
            am: strings(&doc["meridiem"]["am"]),
            pm: strings(&doc["meridiem"]["pm"]),
            weekday_forms,
            part_forms,
        }
    })
}

/// Lower-case tokens; `8i`, `5pm` and `20h` split into number and word, `8:30` and `8.30` stay whole.
fn tokens(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for raw in text.to_lowercase().split_whitespace() {
        let word = raw.trim_matches(|c: char| matches!(c, ',' | '!' | '?' | ';' | '"'));
        let word = word.strip_suffix('.').unwrap_or(word);
        if word.is_empty() {
            continue;
        }
        let digits: String = word
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == ':' || *c == '.')
            .collect();
        if !digits.is_empty() && digits.len() < word.len() {
            out.push(digits.clone());
            out.push(word[digits.len()..].to_string());
        } else {
            out.push(word.to_string());
        }
    }
    out
}

fn clock_digits(token: &str) -> Option<(u32, u32, bool)> {
    let (h, m) = match token.split_once([':', '.']) {
        Some((h, m)) if m.len() == 2 => (h.parse().ok()?, m.parse().ok()?),
        Some(_) => return None,
        None => (token.parse().ok()?, 0),
    };
    (h <= 23 && m <= 59).then_some((h, m, h > 12 || token.starts_with('0')))
}

#[derive(Default)]
struct Parts {
    day: Option<i64>,
    weekday: Option<u32>,
    part: Option<u32>,
    clock: Option<(u32, u32, bool)>,
    pm: Option<bool>,
}

fn split_compound(token: &str, lex: &Lexicon) -> Option<(u32, u32)> {
    lex.weekday_forms.iter().find_map(|(day, n)| {
        let rest = token.strip_prefix(day.as_str())?;
        lex.part_forms
            .iter()
            .find(|(part, _)| part == rest)
            .map(|(_, hour)| (*n, *hour))
    })
}

fn parse_parts(toks: &[String]) -> Option<Parts> {
    let lex = lexicon();
    let mut p = Parts::default();
    let mut i = 0;
    while i < toks.len() {
        let t = toks[i].as_str();
        let prev = i.checked_sub(1).map(|j| toks[j].as_str());
        if let Some(clock) = clock_digits(t) {
            if p.clock.replace(clock).is_some() {
                return None;
            }
        } else if p.clock.is_some()
            && prev.and_then(clock_digits).is_some()
            && lex.am.iter().any(|f| f == t)
        {
            p.pm = Some(false);
        } else if p.clock.is_some() && lex.pm.iter().any(|f| f == t) {
            p.pm = Some(true);
        } else if let Some((day, hour)) = split_compound(t, lex) {
            p.weekday = Some(day);
            p.part = Some(hour);
        } else {
            match lex.words.get(t)? {
                Word::Day(n) => p.day = Some(*n),
                Word::Weekday(n) => p.weekday = Some(*n),
                Word::Part(h) => p.part = Some(*h),
                Word::TomorrowOrMorning => {
                    let after_article =
                        matches!(prev, Some("am" | "z" | "dr" | "der" | "in" | "i" | "the"));
                    if after_article || p.day.is_some() || p.weekday.is_some() {
                        p.part = Some(9);
                    } else {
                        p.day = Some(1);
                    }
                }
                Word::Hour(h) => {
                    if p.clock.replace((*h, 0, false)).is_some() {
                        return None;
                    }
                }
                Word::Half | Word::Quarter | Word::HalfPast => {
                    // halb X = X-1:30; viertel ab|vor X; half|quarter past|to X
                    let word = lex.words.get(t).copied();
                    let mut j = i + 1;
                    let mut relation = None;
                    if word != Some(Word::Half) {
                        relation = lex.words.get(toks.get(j)?.as_str()).copied();
                        if !matches!(relation, Some(Word::Past | Word::To)) {
                            return None;
                        }
                        j += 1;
                    }
                    let hour = match lex.words.get(toks.get(j)?.as_str()) {
                        Some(Word::Hour(h)) => *h,
                        _ => clock_digits(&toks[j]).filter(|c| c.1 == 0).map(|c| c.0)?,
                    };
                    let minutes: i64 = match (word, relation) {
                        (Some(Word::Half), _) => -30,
                        (Some(Word::HalfPast), Some(Word::Past)) => 30,
                        (Some(Word::Quarter), Some(Word::Past)) => 15,
                        (Some(Word::Quarter), Some(Word::To)) => -15,
                        _ => return None,
                    };
                    let total = i64::from(hour) * 60 + minutes;
                    let total = total.rem_euclid(24 * 60);
                    if p.clock
                        .replace(((total / 60) as u32, (total % 60) as u32, false))
                        .is_some()
                    {
                        return None;
                    }
                    i = j;
                }
                Word::ClockSuffix | Word::Filler => {}
                Word::Past | Word::To => return None,
            }
        }
        i += 1;
    }
    Some(p)
}

/// Candidate (hour, minute) pairs in the order they are tried.
fn hours_of_day(p: &Parts) -> Vec<(u32, u32)> {
    let Some((h, m, h24)) = p.clock else {
        return vec![(p.part.unwrap_or(9), 0)];
    };
    if h24 {
        return vec![(h, m)];
    }
    match (p.pm, p.part) {
        (Some(true), _) if h < 12 => vec![(h + 12, m)],
        (Some(false), _) if h == 12 => vec![(0, m)],
        (Some(_), _) => vec![(h, m)],
        (None, Some(part)) if part >= 15 && h < 12 => vec![(h + 12, m)],
        (None, Some(_)) => vec![(h, m)],
        (None, None) if (1..=6).contains(&h) => vec![(h + 12, m)],
        (None, None) if h < 12 => vec![(h, m), (h + 12, m)],
        (None, None) => vec![(h, m)],
    }
}

/// An IANA time zone name ("Europe/Zurich") as the node's zone.
pub fn parse_timezone(name: &str) -> Result<Tz, String> {
    name.parse::<Tz>()
        .map_err(|_| format!("unknown time zone {name:?}"))
}

/// Whether the words name a time relative to now ("in 20 minutes"), which needs no time zone.
pub fn is_relative(text: &str) -> bool {
    let lex = lexicon();
    tokens(text)
        .first()
        .is_some_and(|t| lex.relative.contains(t) || lex.relative_one.contains(t))
}

/// The instant a time slot names, in `tz`, strictly after `now`; `None` when the words
/// are not covered by the lexicon, name no time, or name a time that has passed.
pub fn resolve(text: &str, now: DateTime<Utc>, tz: Tz) -> Option<DateTime<Tz>> {
    let lex = lexicon();
    let mut toks = tokens(text);
    // Leading fillers ("later in two hours") are skipped; "i"/"in" open a relative time.
    while toks.len() > 1
        && lex.words.get(&toks[0]) == Some(&Word::Filler)
        && !lex.relative.contains(&toks[0])
    {
        toks.remove(0);
    }
    let first = toks.first()?;
    let local_now = now.with_timezone(&tz);
    if lex.relative.contains(first) || lex.relative_one.contains(first) {
        let mut rest = toks[1..].join(" ");
        if lex.relative_one.contains(first) {
            rest = format!("1 {rest}");
        }
        let seconds = crate::node_exec::duration_seconds(&rest)?;
        return Some(local_now + Duration::seconds(i64::try_from(seconds).ok()?));
    }
    let p = parse_parts(&toks)?;
    if p.day.is_none() && p.weekday.is_none() && p.part.is_none() && p.clock.is_none() {
        return None;
    }
    let candidates = hours_of_day(&p);
    let today = local_now.date_naive();
    let mut date: NaiveDate = match (p.day, p.weekday) {
        (Some(_), Some(_)) => return None,
        (Some(n), None) => today + Duration::days(n),
        (None, Some(w)) => {
            let ahead =
                (i64::from(w) - i64::from(today.weekday().num_days_from_monday())).rem_euclid(7);
            today + Duration::days(ahead)
        }
        (None, None) => today,
    };
    let first_after = |date: NaiveDate| {
        candidates.iter().find_map(|&(hour, minute)| {
            let local = date.and_time(NaiveTime::from_hms_opt(hour, minute, 0)?);
            tz.from_local_datetime(&local)
                .earliest()
                .filter(|t| *t > local_now)
        })
    };
    if let Some(when) = first_after(date) {
        return Some(when);
    }
    match (p.day, p.weekday) {
        (None, Some(_)) => date += Duration::days(7),
        (None, None) => date += Duration::days(1),
        _ => return None,
    }
    first_after(date)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tuesday 2026-10-20, 19:30 in Zurich (CEST, UTC+2).
    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 10, 20, 17, 30, 0).unwrap()
    }

    fn at(text: &str) -> Option<String> {
        resolve(text, now(), chrono_tz::Europe::Zurich)
            .map(|t| t.format("%a %Y-%m-%d %H:%M").to_string())
    }

    #[test]
    fn swiss_german_german_and_english_times_resolve() {
        assert_eq!(at("morn am füfi").as_deref(), Some("Wed 2026-10-21 17:00"));
        assert_eq!(
            at("morn am achti am Morge").as_deref(),
            Some("Wed 2026-10-21 08:00")
        );
        assert_eq!(at("morn am 8i").as_deref(), Some("Wed 2026-10-21 08:00"));
        assert_eq!(at("morgen um 8").as_deref(), Some("Wed 2026-10-21 08:00"));
        assert_eq!(
            at("tomorrow at 8am").as_deref(),
            Some("Wed 2026-10-21 08:00")
        );
        assert_eq!(
            at("am Mäntigmorge").as_deref(),
            Some("Mon 2026-10-26 09:00")
        );
        assert_eq!(
            at("Mändig am Morge").as_deref(),
            Some("Mon 2026-10-26 09:00")
        );
        assert_eq!(
            at("am Montagmorgen").as_deref(),
            Some("Mon 2026-10-26 09:00")
        );
        assert_eq!(
            at("on Friday at 2pm").as_deref(),
            Some("Fri 2026-10-23 14:00")
        );
        assert_eq!(
            at("am Fritig am zwöi").as_deref(),
            Some("Fri 2026-10-23 14:00")
        );
        assert_eq!(
            at("am Sunntig z Abe").as_deref(),
            Some("Sun 2026-10-25 19:00")
        );
        assert_eq!(
            at("am Sonntagabend").as_deref(),
            Some("Sun 2026-10-25 19:00")
        );
        assert_eq!(at("hüt am Abig"), None);
        assert_eq!(at("hüt am nüni").as_deref(), Some("Tue 2026-10-20 21:00"));
        assert_eq!(
            at("halbi nüni am Abe").as_deref(),
            Some("Tue 2026-10-20 20:30")
        );
        assert_eq!(
            at("morn viertu ab drü").as_deref(),
            Some("Wed 2026-10-21 15:15")
        );
        assert_eq!(
            at("quarter to nine tomorrow").as_deref(),
            Some("Wed 2026-10-21 08:45")
        );
        assert_eq!(
            at("half past seven tomorrow").as_deref(),
            Some("Wed 2026-10-21 07:30")
        );
        assert_eq!(at("14:30").as_deref(), Some("Wed 2026-10-21 14:30"));
        assert_eq!(at("am Mittag").as_deref(), Some("Wed 2026-10-21 12:00"));
        assert_eq!(at("tonight").as_deref(), Some("Tue 2026-10-20 21:00"));
        assert_eq!(at("morgen früh").as_deref(), Some("Wed 2026-10-21 09:00"));
    }

    #[test]
    fn relative_times_use_the_duration_lexicon() {
        assert_eq!(at("in 20 Minute").as_deref(), Some("Tue 2026-10-20 19:50"));
        assert_eq!(at("i 20 Minute").as_deref(), Some("Tue 2026-10-20 19:50"));
        assert_eq!(at("inere Stund").as_deref(), Some("Tue 2026-10-20 20:30"));
        assert_eq!(at("ines Stündli").as_deref(), Some("Tue 2026-10-20 20:30"));
        assert_eq!(at("in an hour").as_deref(), Some("Tue 2026-10-20 20:30"));
        assert_eq!(
            at("in einer Stunde").as_deref(),
            Some("Tue 2026-10-20 20:30")
        );
    }

    #[test]
    fn daylight_saving_time_is_respected() {
        // Clocks go back on Sunday 2026-10-25: 09:00 local is 08:00 UTC that day.
        let t = resolve(
            "am Sunntig am nüni am Morge",
            now(),
            chrono_tz::Europe::Zurich,
        )
        .unwrap();
        assert_eq!(
            t.with_timezone(&Utc).format("%Y-%m-%dT%H:%M").to_string(),
            "2026-10-25T08:00"
        );
    }

    #[test]
    fn unknown_words_past_times_and_contradictions_are_refused() {
        assert_eq!(at("irgendwenn"), None);
        assert_eq!(at("morn oder so"), None);
        assert_eq!(at("hüt am Morge"), None);
        assert_eq!(at("hüt am achti am Morge"), None);
        assert_eq!(at("morn am Mäntig"), None);
        assert_eq!(at("25:00"), None);
        assert_eq!(at(""), None);
    }

    #[test]
    fn every_time_in_the_linguist_phrasebook_resolves() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../local-training/linguist_phrasebook.json");
        let book: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        for entry in book["pools"]["reminder_time"].as_array().unwrap() {
            for forms in entry.as_object().unwrap().values() {
                for form in forms.as_array().unwrap() {
                    // 06:00 in Zurich, so "today at 5pm" lies ahead.
                    let morning = Utc.with_ymd_and_hms(2026, 10, 20, 4, 0, 0).unwrap();
                    let form = form.as_str().unwrap();
                    assert!(
                        resolve(form, morning, chrono_tz::Europe::Zurich).is_some(),
                        "{form}"
                    );
                }
            }
        }
    }

    #[test]
    fn time_lexicon_forms_are_lowercase_and_unique() {
        let doc: Value = serde_json::from_str(TIME_LEXICON_JSON).unwrap();
        let mut seen = std::collections::BTreeMap::new();
        let mut visit = |section: &str, value: &Value| {
            let lists: Vec<&Value> = match value {
                Value::Object(map) => map.values().map(|v| v.get("forms").unwrap_or(v)).collect(),
                list => vec![list],
            };
            for form in lists.into_iter().flat_map(|l| l.as_array().unwrap()) {
                let form = form.as_str().unwrap().to_string();
                assert_eq!(form, form.to_lowercase());
                seen.entry(form)
                    .or_insert_with(Vec::new)
                    .push(section.to_string());
            }
        };
        for (section, value) in doc.as_object().unwrap() {
            if section == "relative" || section == "meridiem" {
                for (name, inner) in value.as_object().unwrap() {
                    visit(&format!("{section}.{name}"), inner);
                }
            } else if !matches!(section.as_str(), "v" | "about") {
                visit(section, value);
            }
        }
        // "am", "i" and "in" are read by position (after a number, first word), else fillers.
        for (form, sections) in seen {
            let allowed = matches!(form.as_str(), "am" | "i" | "in") && sections.len() == 2;
            assert!(sections.len() == 1 || allowed, "{form} in {sections:?}");
        }
    }

    #[test]
    fn a_time_that_passed_today_moves_to_tomorrow() {
        assert_eq!(
            at("am sibni am Morge").as_deref(),
            Some("Wed 2026-10-21 07:00")
        );
        assert_eq!(
            at("am Zischtig am Morge").as_deref(),
            Some("Tue 2026-10-27 09:00")
        );
    }
}
