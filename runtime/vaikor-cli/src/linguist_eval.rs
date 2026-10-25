// Copyright 2026 VAIEV
// SPDX-License-Identifier: Apache-2.0
//! Model -1 release gate (ROADMAP 13e): score linguist replies through the Core functions the
//! runtime uses, so the reported numbers measure what ships.
//!
//! Every row goes through `IntentCatalog::understand`, the runtime entry point: the utterance
//! check, `render_prompt` over the full catalog, the model call (`chat_request`,
//! `reply_from_response`) and `verify_proposal_for`. In `score` mode the model is a recorded
//! completion, in `serve` mode it is the node's local model endpoint (`LocalLinguist`).
//! What the Core keeps is then compared with the expected `lang`, `intent`, `slots` and
//! follow-ups. Nothing here changes what the Core accepts.
//!
//! Plan instantiation and the Cedar flow check after the linguist gate are not part of this
//! verdict (they need a node workspace).

use std::cell::RefCell;
use std::io::{BufRead, Write};

use serde_json::{json, Map, Value};

use crate::linguist::{
    answer_from_content, checked_utterance, IntentCatalog, LinguistEnvelope, LinguistModel,
    LinguistOutput, Ordered,
};

/// The expectation for one row: `lang` is optional (hand-written probes name none). It is one
/// locale or a non-empty set of them (an utterance German and Swiss German write the same):
/// either is right, and the first is the language the row was generated in. A slot
/// whose expected value is `null` is not checked (a free-text slot of a hand-written probe):
/// it may be kept with any value or be absent. Every slot not named is unexpected.
#[derive(Debug, Clone)]
pub struct Expected {
    pub lang: Option<Vec<String>>,
    pub intent: Option<String>,
    pub slots: Map<String, Value>,
    pub then: Vec<(String, Map<String, Value>)>,
}

impl Expected {
    /// Reads `lang`, `intent`, `slots` and `then[].{intent, slots}`; other members of a full
    /// envelope are ignored (the Core re-derives them).
    pub fn from_value(value: &Value) -> Result<Self, String> {
        let object = value.as_object().ok_or("expected is not an object")?;
        let lang = match object.get("lang") {
            None | Some(Value::Null) => None,
            Some(Value::String(lang)) => Some(vec![lang.clone()]),
            Some(Value::Array(items)) if !items.is_empty() => Some(
                items
                    .iter()
                    .map(|v| v.as_str().map(str::to_string))
                    .collect::<Option<_>>()
                    .ok_or("expected.lang must hold locale strings")?,
            ),
            Some(_) => {
                return Err("expected.lang is not a string or a non-empty array of strings".into())
            }
        };
        let intent = match object.get("intent") {
            Some(Value::Null) => None,
            Some(Value::String(id)) => Some(id.clone()),
            _ => return Err("expected.intent must be a string or null".into()),
        };
        let slots = string_map(object.get("slots"), "expected.slots")?;
        let mut then = Vec::new();
        if let Some(items) = object.get("then") {
            for (index, item) in items
                .as_array()
                .ok_or("expected.then is not an array")?
                .iter()
                .enumerate()
            {
                let next = item
                    .get("intent")
                    .and_then(Value::as_str)
                    .ok_or_else(|| format!("expected.then[{index}].intent is not a string"))?;
                let given =
                    string_map(item.get("slots"), &format!("expected.then[{index}].slots"))?;
                then.push((next.to_string(), given));
            }
        }
        Ok(Self {
            lang,
            intent,
            slots,
            then,
        })
    }

    /// Whether the Core asks back for this expectation (a missing required slot or no intent).
    /// Every expected language must be a catalog locale.
    fn needs_clarification(&self, catalog: &IntentCatalog) -> Result<bool, String> {
        if let Some(unknown) = self
            .lang
            .iter()
            .flatten()
            .find(|lang| !catalog.locales.contains(lang))
        {
            return Err(format!("expected.lang: unknown locale {unknown:?}"));
        }
        let lang = self
            .lang
            .as_ref()
            .map_or_else(|| catalog.locales[0].clone(), |langs| langs[0].clone());
        let then: Vec<(String, Ordered<String>)> = self
            .then
            .iter()
            .map(|(next, given)| (next.clone(), ordered(given)))
            .collect();
        let envelope = catalog
            .derive_with_then(&lang, self.intent.as_deref(), &ordered(&self.slots), &then)
            .map_err(|e| format!("expected: {e}"))?;
        Ok(envelope.clarification_needed)
    }
}

fn string_map(value: Option<&Value>, what: &str) -> Result<Map<String, Value>, String> {
    let map = match value {
        None => return Ok(Map::new()),
        Some(value) => value
            .as_object()
            .ok_or_else(|| format!("{what} is not an object"))?,
    };
    if map.values().any(|v| !v.is_string() && !v.is_null()) {
        return Err(format!("{what} values must be strings or null"));
    }
    Ok(map.clone())
}

/// Slots for `derive`; an unchecked (`null`) slot counts as given.
fn ordered(map: &Map<String, Value>) -> Ordered<String> {
    Ordered(
        map.iter()
            .map(|(k, v)| (k.clone(), v.as_str().unwrap_or("(unchecked)").to_string()))
            .collect(),
    )
}

/// Slot values match exactly, apart from leading and trailing whitespace: case and inner
/// spacing carry meaning (code, quoted text, names), so a benchmark must not erase them.
fn same_value(a: &str, b: &str) -> bool {
    a.trim() == b.trim()
}

/// A model that answers with one recorded completion, post-processed like a served reply.
struct Recorded<'a>(&'a str);

impl LinguistModel for Recorded<'_> {
    fn propose(&self, _system: &str, _user: &str) -> Result<String, String> {
        Ok(answer_from_content(self.0))
    }
}

/// Wraps a model and keeps its reply, so a refusal can be attributed to its stage.
struct Recording<'a> {
    inner: &'a dyn LinguistModel,
    reply: RefCell<Option<Result<String, String>>>,
}

impl LinguistModel for Recording<'_> {
    fn propose(&self, system: &str, user: &str) -> Result<String, String> {
        let reply = self.inner.propose(system, user);
        *self.reply.borrow_mut() = Some(reply.clone());
        reply
    }

    fn output(&self) -> LinguistOutput {
        self.inner.output()
    }
}

/// The exact runtime prompt and request for one utterance (`render-prompt` mode) for the
/// `output` form. `intent_ids` limits and orders the catalog (training data only; the
/// runtime shows all). `request` is the body the runtime sends, parsed.
pub fn render_row(
    catalog: &IntentCatalog,
    output: LinguistOutput,
    row: &Value,
) -> Result<Value, String> {
    let utterance = row
        .get("utterance")
        .and_then(Value::as_str)
        .ok_or("row.utterance is not a string")?;
    let ids: Option<Vec<&str>> = match row.get("intent_ids") {
        None | Some(Value::Null) => None,
        Some(Value::Array(items)) => Some(
            items
                .iter()
                .map(|v| v.as_str().ok_or("row.intent_ids must hold strings"))
                .collect::<Result<_, _>>()?,
        ),
        Some(_) => return Err("row.intent_ids is not an array".into()),
    };
    let utterance = checked_utterance(utterance)?;
    let (system, user) = catalog.render_prompt_as(output, utterance, ids.as_deref())?;
    let request: Value = serde_json::from_str(&catalog.request_body(output, &system, &user))
        .map_err(|e| format!("request: {e}"))?;
    Ok(json!({"utterance": utterance, "system": system, "user": user, "request": request}))
}

/// Score one recorded completion (`score` mode): row `{utterance, completion, expected}`.
pub fn score_row(catalog: &IntentCatalog, row: &Value) -> Result<Value, String> {
    let completion = row
        .get("completion")
        .and_then(Value::as_str)
        .ok_or("row.completion is not a string")?;
    evaluate_row(catalog, &Recorded(completion), row)
}

/// Ask `model` about one utterance and score the reply (`serve` mode): row `{utterance, expected}`.
pub fn evaluate_row(
    catalog: &IntentCatalog,
    model: &dyn LinguistModel,
    row: &Value,
) -> Result<Value, String> {
    let utterance = row
        .get("utterance")
        .and_then(Value::as_str)
        .ok_or("row.utterance is not a string")?;
    let expected = Expected::from_value(row.get("expected").ok_or("row.expected is missing")?)?;
    let clarification_expected = expected.needs_clarification(catalog)?;
    let recording = Recording {
        inner: model,
        reply: RefCell::new(None),
    };
    let verdict = catalog.understand(&recording, utterance);
    let reply = recording.reply.into_inner();
    let completion = reply.as_ref().and_then(|r| r.as_ref().ok()).cloned();
    let legacy_effective = completion
        .as_deref()
        .is_some_and(|text| legacy_effective(text, &expected));
    let mut out = match verdict {
        Ok(verified) => {
            let mut out = compare(&verified.envelope, &expected, clarification_expected);
            out.insert("core_accepts".into(), json!(true));
            out.insert("refusal".into(), Value::Null);
            out.insert("corrections".into(), json!(verified.corrections));
            out.insert(
                "kept".into(),
                serde_json::to_value(&verified.envelope).unwrap(),
            );
            out
        }
        Err(reason) => {
            let stage = match &reply {
                None => "utterance",
                Some(Err(_)) => "model",
                Some(Ok(_)) if reason.starts_with("linguist-envelope-invalid") => "envelope",
                Some(Ok(_)) => "derive",
            };
            let mut out = Map::new();
            out.insert("core_accepts".into(), json!(false));
            out.insert("refusal".into(), json!({"stage": stage, "reason": reason}));
            out.insert("corrections".into(), json!([]));
            out.insert("kept".into(), Value::Null);
            for key in [
                "lang_ok",
                "lang_strict_ok",
                "intent_ok",
                "slots_ok",
                "semantic_ok",
            ] {
                out.insert(key.into(), json!(false));
            }
            for key in [
                "invented_slots",
                "missing_slots",
                "wrong_slots",
                "extra_followups",
                "missing_followups",
            ] {
                out.insert(key.into(), json!([]));
            }
            // A refused reply asks nothing back and does nothing.
            out.insert("clarification_ok".into(), json!(false));
            out.insert("unintended_action".into(), json!(false));
            out
        }
    };
    out.insert(
        "clarification_expected".into(),
        json!(clarification_expected),
    );
    out.insert("legacy_effective".into(), json!(legacy_effective));
    out.insert("completion".into(), json!(completion));
    Ok(Value::Object(out))
}

/// Compare what the Core keeps with the expectation.
fn compare(
    kept: &LinguistEnvelope,
    expected: &Expected,
    clarification_expected: bool,
) -> Map<String, Value> {
    let kept_then: Vec<&str> = kept.then.iter().map(|f| f.intent.as_str()).collect();
    let expected_then: Vec<&str> = expected.then.iter().map(|(i, _)| i.as_str()).collect();
    let intent_ok = kept.intent == expected.intent && kept_then == expected_then;
    let lang_ok = expected
        .lang
        .as_ref()
        .map(|langs| langs.contains(&kept.lang));
    let lang_strict_ok = expected.lang.as_ref().map(|langs| langs[0] == kept.lang);
    let (mut invented, mut missing, mut wrong) = (Vec::new(), Vec::new(), Vec::new());
    let empty = Map::new();
    let positions = 1 + kept.then.len().max(expected.then.len());
    for index in 0..positions {
        let prefix = if index == 0 {
            String::new()
        } else {
            format!("then[{}].", index - 1)
        };
        let got: Vec<(&str, &str)> = match index {
            0 => kept
                .slots
                .0
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect(),
            i => kept.then.get(i - 1).map_or_else(Vec::new, |f| {
                f.slots
                    .0
                    .iter()
                    .map(|(k, v)| (k.as_str(), v.as_str()))
                    .collect()
            }),
        };
        let want = match index {
            0 => &expected.slots,
            i => expected.then.get(i - 1).map_or(&empty, |(_, s)| s),
        };
        for (name, value) in &got {
            match want.get(*name) {
                None => invented.push(format!("{prefix}{name}")),
                Some(Value::String(target)) if !same_value(value, target) => {
                    wrong.push(format!("{prefix}{name}"))
                }
                Some(_) => {}
            }
        }
        // A `null` target accepts any value but still requires the slot to be given.
        for (name, _target) in want {
            if !got.iter().any(|(k, _)| k == name) {
                missing.push(format!("{prefix}{name}"));
            }
        }
    }
    let extra: Vec<&str> = kept_then
        .iter()
        .skip(expected_then.len())
        .copied()
        .collect();
    let absent: Vec<&str> = expected_then
        .iter()
        .skip(kept_then.len())
        .copied()
        .collect();
    let slots_ok = invented.is_empty() && missing.is_empty() && wrong.is_empty();
    // The Core goes on to plan an intent that is not exactly the one asked for.
    let actionable = kept.intent.is_some() && !kept.clarification_needed;
    let unintended = actionable && !(intent_ok && slots_ok);
    let mut out = Map::new();
    out.insert("lang_ok".into(), json!(lang_ok));
    out.insert("lang_strict_ok".into(), json!(lang_strict_ok));
    out.insert("intent_ok".into(), json!(intent_ok));
    out.insert("slots_ok".into(), json!(slots_ok));
    out.insert(
        "semantic_ok".into(),
        json!(lang_ok != Some(false) && intent_ok && slots_ok),
    );
    out.insert("invented_slots".into(), json!(invented));
    out.insert("missing_slots".into(), json!(missing));
    out.insert("wrong_slots".into(), json!(wrong));
    out.insert("extra_followups".into(), json!(extra));
    out.insert("missing_followups".into(), json!(absent));
    out.insert(
        "clarification_ok".into(),
        json!(kept.clarification_needed == clarification_expected),
    );
    out.insert("unintended_action".into(), json!(unintended));
    out
}

/// The pre-gate metric, for comparison only: the raw proposal's `lang`, `intent`, `slots` and
/// follow-ups equal the expectation exactly, whether or not the Core accepts the proposal.
fn legacy_effective(completion: &str, expected: &Expected) -> bool {
    let Ok(Value::Object(proposed)) = serde_json::from_str::<Value>(completion) else {
        return false;
    };
    let follow_ups = |items: Option<&Value>| -> Option<Vec<(Value, Value)>> {
        match items {
            None => Some(Vec::new()),
            Some(Value::Array(items)) => Some(
                items
                    .iter()
                    .map(|f| {
                        (
                            f.get("intent").cloned().unwrap_or(Value::Null),
                            f.get("slots").cloned().unwrap_or(Value::Null),
                        )
                    })
                    .collect(),
            ),
            Some(_) => None,
        }
    };
    let want: Vec<(Value, Value)> = expected
        .then
        .iter()
        .map(|(i, s)| (json!(i), Value::Object(s.clone())))
        .collect();
    expected.lang.as_ref().is_none_or(|langs| {
        proposed
            .get("lang")
            .and_then(Value::as_str)
            .is_some_and(|lang| langs.iter().any(|l| l == lang))
    }) && proposed.get("intent") == Some(&json!(expected.intent))
        && proposed
            .get("slots")
            .is_some_and(|slots| same_slots(slots, &expected.slots))
        && follow_ups(proposed.get("then")).is_some_and(|got| {
            got.len() == want.len()
                && got
                    .iter()
                    .zip(&want)
                    .all(|((gi, gs), (wi, ws))| gi == wi && same_slots(gs, ws.as_object().unwrap()))
        })
}

/// Exact slot equality of a raw proposal; an unchecked (`null`) expected slot matches anything.
fn same_slots(got: &Value, want: &Map<String, Value>) -> bool {
    let Some(got) = got.as_object() else {
        return false;
    };
    got.keys().all(|name| want.contains_key(name))
        && want
            .iter()
            .all(|(name, target)| target.is_null() || got.get(name) == Some(target))
}

/// The modes of `vaikor linguist-eval`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    RenderPrompt,
    Score,
    Serve,
}

impl Mode {
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "render-prompt" => Some(Self::RenderPrompt),
            "score" => Some(Self::Score),
            "serve" => Some(Self::Serve),
            _ => None,
        }
    }
}

/// Run one mode over JSONL rows; one JSON line out per row, in order. A malformed row yields
/// `{"error": ...}` and the run fails (returns the number of bad rows) after the last row.
/// `form` is the output form `render-prompt` renders; `serve` uses the model's own form.
pub fn run(
    catalog: &IntentCatalog,
    mode: Mode,
    form: LinguistOutput,
    model: Option<&dyn LinguistModel>,
    input: impl BufRead,
    mut output: impl Write,
) -> Result<usize, String> {
    let mut bad = 0;
    for (index, line) in input.lines().enumerate() {
        let line = line.map_err(|e| format!("input: {e}"))?;
        if line.trim().is_empty() {
            continue;
        }
        let result = serde_json::from_str::<Value>(&line)
            .map_err(|e| format!("not JSON: {e}"))
            .and_then(|row| match (mode, model) {
                (Mode::RenderPrompt, _) => render_row(catalog, form, &row),
                (Mode::Score, _) => score_row(catalog, &row),
                (Mode::Serve, Some(model)) => evaluate_row(catalog, model, &row),
                (Mode::Serve, None) => Err("serve mode needs a model endpoint".into()),
            });
        let value = result.unwrap_or_else(|e| {
            bad += 1;
            json!({"error": format!("line {}: {e}", index + 1)})
        });
        writeln!(output, "{value}").map_err(|e| format!("output: {e}"))?;
    }
    output.flush().map_err(|e| format!("output: {e}"))?;
    Ok(bad)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linguist::{
        chat_request, reply_from_response, LocalLinguist, SYSTEM_PROMPT, SYSTEM_PROMPT_COMPACT,
    };

    fn catalog() -> IntentCatalog {
        IntentCatalog::builtin().unwrap()
    }

    fn score(utterance: &str, completion: Value, expected: Value) -> Value {
        let row = json!({"utterance": utterance, "completion": completion.to_string(), "expected": expected});
        score_row(&catalog(), &row).unwrap()
    }

    fn derived(lang: &str, intent: Option<&str>, slots: &[(&str, &str)]) -> Value {
        let slots = Ordered(
            slots
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        );
        serde_json::to_value(catalog().derive(lang, intent, &slots).unwrap()).unwrap()
    }

    const SEND: &str = "Write to Nina about the concert";

    fn send() -> Value {
        derived(
            "en",
            Some("messaging.send"),
            &[("recipient", "Nina"), ("topic", "the concert")],
        )
    }

    #[test]
    fn a_correct_reply_is_accepted_and_semantically_right() {
        let out = score(SEND, send(), send());
        assert_eq!(out["core_accepts"], true);
        assert_eq!(out["refusal"], Value::Null);
        assert_eq!(out["corrections"], json!([]));
        for key in [
            "lang_ok",
            "intent_ok",
            "slots_ok",
            "semantic_ok",
            "clarification_ok",
            "legacy_effective",
        ] {
            assert_eq!(out[key], true, "{key}");
        }
        assert_eq!(out["unintended_action"], false);
        assert_eq!(out["clarification_expected"], false);
        assert_eq!(out["kept"]["intent"], "messaging.send");
    }

    #[test]
    fn slot_values_compare_exactly_case_included() {
        let utterance = "Write to Nina about the Concert";
        let expected = derived(
            "en",
            Some("messaging.send"),
            &[("recipient", "Nina"), ("topic", "the Concert")],
        );
        let reply = derived(
            "en",
            Some("messaging.send"),
            &[("recipient", "Nina"), ("topic", "the concert")],
        );
        let out = score(utterance, reply, expected);
        assert_eq!(out["slots_ok"], false, "{out}");
        assert_eq!(out["semantic_ok"], false);
        assert_eq!(out["wrong_slots"], json!(["topic"]));
    }

    #[test]
    fn a_wildcard_slot_must_still_be_given() {
        let mut expected = send();
        expected["slots"]["recipient"] = Value::Null;
        let reply = derived("en", Some("messaging.send"), &[("topic", "the concert")]);
        let out = score(SEND, reply, expected);
        assert_eq!(out["missing_slots"], json!(["recipient"]), "{out}");
        assert_eq!(out["semantic_ok"], false);
    }

    #[test]
    fn a_forbidden_member_is_a_core_refusal_although_the_old_metric_counted_it() {
        let mut reply = send();
        reply["residency"] = json!(["CH"]);
        let out = score(SEND, reply, send());
        assert_eq!(out["core_accepts"], false);
        assert_eq!(out["refusal"]["stage"], "envelope");
        assert!(out["refusal"]["reason"]
            .as_str()
            .unwrap()
            .contains("unexpected member residency"));
        assert_eq!(out["semantic_ok"], false);
        assert_eq!(out["unintended_action"], false);
        assert_eq!(out["legacy_effective"], true);
    }

    #[test]
    fn non_json_and_invalid_utterances_are_refused_at_their_stage() {
        let row = json!({"utterance": SEND, "completion": "sure, here it is", "expected": send()});
        let out = score_row(&catalog(), &row).unwrap();
        assert_eq!(out["refusal"]["stage"], "envelope");
        assert_eq!(out["legacy_effective"], false);
        let row = json!({"utterance": "   ", "completion": send().to_string(), "expected": send()});
        let out = score_row(&catalog(), &row).unwrap();
        assert_eq!(out["refusal"]["stage"], "utterance");
        assert_eq!(out["completion"], Value::Null);
    }

    #[test]
    fn an_invented_slot_is_reported_and_the_action_is_unintended() {
        let reply = derived(
            "en",
            Some("task.code"),
            &[("description", "a CSV parser"), ("language", "Rust")],
        );
        let expected = derived("en", Some("task.code"), &[("description", "a CSV parser")]);
        let out = score("Write me a CSV parser in Rust", reply, expected);
        assert_eq!(out["core_accepts"], true);
        assert_eq!(out["intent_ok"], true);
        assert_eq!(out["slots_ok"], false);
        assert_eq!(out["invented_slots"], json!(["language"]));
        assert_eq!(out["unintended_action"], true);
    }

    #[test]
    fn a_slot_the_core_drops_is_not_kept_and_shows_as_a_correction() {
        // `topic` is verbatim: a value that does not occur in the utterance is dropped (L7),
        // the Core asks back instead of acting.
        let reply = derived(
            "en",
            Some("messaging.send"),
            &[("recipient", "Nina"), ("topic", "the next weekend")],
        );
        let out = score(SEND, reply, send());
        assert_eq!(out["core_accepts"], true);
        assert!(out["corrections"]
            .as_array()
            .unwrap()
            .contains(&json!("slot-ungrounded:topic")));
        assert_eq!(out["missing_slots"], json!(["topic"]));
        assert_eq!(out["invented_slots"], json!([]));
        assert_eq!(out["clarification_ok"], false);
        assert_eq!(out["unintended_action"], false);
        assert_eq!(out["legacy_effective"], false);
    }

    #[test]
    fn an_extra_follow_up_is_reported() {
        let utterance = "Summarize the report and send it to Lea";
        let expected = derived("en", Some("task.summarize"), &[("source", "the report")]);
        let mut reply = expected.clone();
        reply["then"] = json!([{"intent": "messaging.send", "slots": {"recipient": "Lea"}}]);
        let out = score(utterance, reply, expected);
        assert_eq!(out["core_accepts"], true);
        assert_eq!(out["extra_followups"], json!(["messaging.send"]));
        assert_eq!(out["invented_slots"], json!(["then[0].recipient"]));
        assert_eq!(out["intent_ok"], false);
        assert_eq!(out["unintended_action"], true);
    }

    #[test]
    fn a_declared_follow_up_is_scored_with_its_slots() {
        let utterance = "Summarize the report and send it to Lea";
        let expected = json!({"lang": "en", "intent": "task.summarize", "slots": {"source": "the report"},
            "then": [{"intent": "messaging.send", "slots": {"recipient": "Lea"}}]});
        let mut reply = derived("en", Some("task.summarize"), &[("source", "the report")]);
        reply["then"] = json!([{"intent": "messaging.send", "slots": {"recipient": "Lea"}}]);
        let out = score(utterance, reply.clone(), expected.clone());
        assert_eq!(out["semantic_ok"], true, "{out}");
        assert_eq!(out["extra_followups"], json!([]));
        let mut lost = reply;
        lost.as_object_mut().unwrap().remove("then");
        let out = score(utterance, lost, expected);
        assert_eq!(out["missing_followups"], json!(["messaging.send"]));
        assert_eq!(out["intent_ok"], false);
    }

    #[test]
    fn clarification_is_right_when_the_core_asks_for_the_missing_slot() {
        let utterance = "Remind me about the laundry";
        let expected = derived(
            "en",
            Some("scheduling.remind"),
            &[("subject", "the laundry")],
        );
        let out = score(utterance, expected.clone(), expected.clone());
        assert_eq!(out["clarification_expected"], true);
        assert_eq!(out["clarification_ok"], true);
        assert_eq!(out["unintended_action"], false);
        // An invented time fills the gap: no question, and an action nobody asked for.
        let reply = derived(
            "en",
            Some("scheduling.remind"),
            &[("subject", "the laundry"), ("time", "laundry")],
        );
        let out = score(utterance, reply, expected);
        assert_eq!(out["clarification_ok"], false);
        assert_eq!(out["unintended_action"], true);
        assert_eq!(out["invented_slots"], json!(["time"]));
    }

    #[test]
    fn intent_null_asks_back_and_a_wrong_intent_is_unintended() {
        let none = derived("gsw", None, &[]);
        let out = score("isch scho guet so", none.clone(), none.clone());
        assert_eq!(out["clarification_expected"], true);
        assert_eq!(out["semantic_ok"], true);
        let out = score(
            "isch scho guet so",
            derived(
                "gsw",
                Some("task.note"),
                &[("content", "isch scho guet so")],
            ),
            none,
        );
        assert_eq!(out["intent_ok"], false);
        assert_eq!(out["unintended_action"], true);
    }

    #[test]
    fn probes_without_lang_compare_slots_exactly() {
        let expected = json!({"intent": "messaging.send", "slots": {"recipient": "Nina", "topic": "the concert"}});
        let out = score(SEND, send(), expected);
        assert_eq!(out["lang_ok"], Value::Null);
        assert_eq!(out["semantic_ok"], true);
        let expected = json!({"intent": "messaging.send", "slots": {"recipient": "nina", "topic": "the concert"}});
        let out = score(SEND, send(), expected);
        assert_eq!(out["wrong_slots"], json!(["recipient"]));
        let expected = json!({"intent": "messaging.send", "slots": {"recipient": "Lea", "topic": "the concert"}});
        let out = score(SEND, send(), expected);
        assert_eq!(out["wrong_slots"], json!(["recipient"]));
        assert_eq!(out["slots_ok"], false);
        assert_eq!(out["unintended_action"], true);
    }

    #[test]
    fn an_unchecked_slot_may_have_any_value_but_must_be_given_and_others_are_invented() {
        let expected =
            json!({"intent": "messaging.send", "slots": {"recipient": "Nina", "topic": null}});
        let out = score(SEND, send(), expected.clone());
        assert_eq!(out["semantic_ok"], true, "{out}");
        assert_eq!(out["clarification_expected"], false);
        assert_eq!(out["legacy_effective"], true);
        let asked = derived("en", Some("messaging.send"), &[("recipient", "Nina")]);
        let out = score(SEND, asked, expected);
        assert_eq!(out["semantic_ok"], false);
        assert_eq!(out["missing_slots"], json!(["topic"]));
        let out = score(
            SEND,
            send(),
            json!({"intent": "messaging.send", "slots": {"recipient": "Nina"}}),
        );
        assert_eq!(out["invented_slots"], json!(["topic"]));
        assert_eq!(out["semantic_ok"], false);
    }

    #[test]
    fn an_ambiguous_row_accepts_either_language_of_its_set_and_reports_the_strict_one() {
        let utterance = "Such plan.odt in Documents";
        let reply = |lang: &str| {
            json!({"v": "0.2", "lang": lang, "intent": "files.find", "missing": [],
                "slots": {"query": "plan.odt", "folder": "Documents"}})
        };
        let mut expected = reply("de");
        expected["lang"] = json!(["de", "gsw"]);
        let out = score(utterance, reply("gsw"), expected.clone());
        assert_eq!(out["lang_ok"], true, "{out}");
        assert_eq!(out["lang_strict_ok"], false);
        assert_eq!(out["semantic_ok"], true);
        assert_eq!(out["legacy_effective"], true);
        let out = score(utterance, reply("de"), expected.clone());
        assert_eq!(out["lang_ok"], true, "{out}");
        assert_eq!(out["lang_strict_ok"], true);
        let out = score(utterance, reply("en"), expected.clone());
        assert_eq!(out["lang_ok"], false, "{out}");
        assert_eq!(out["lang_strict_ok"], false);
        assert_eq!(out["semantic_ok"], false);
        assert_eq!(out["legacy_effective"], false);
        // A single language is strict either way; a probe without one checks neither.
        let out = score(SEND, send(), send());
        assert_eq!(out["lang_strict_ok"], true, "{out}");
        let probe = json!({"intent": "messaging.send", "slots": {"recipient": "Nina", "topic": "the concert"}});
        assert_eq!(score(SEND, send(), probe)["lang_strict_ok"], Value::Null);
    }

    #[test]
    fn an_expected_lang_of_any_other_shape_refuses_the_row() {
        for lang in [
            json!([]),
            json!(["de", 1]),
            json!(7),
            json!({"de": true}),
            json!(["de", "xx"]),
        ] {
            let mut expected = send();
            expected["lang"] = lang.clone();
            let row =
                json!({"utterance": SEND, "completion": send().to_string(), "expected": expected});
            assert!(score_row(&catalog(), &row).is_err(), "{lang}");
        }
    }

    #[test]
    fn a_reasoning_block_is_stripped_as_in_a_served_reply() {
        let completion = format!("<think>\n</think>\n\n{}\n", send());
        let row = json!({"utterance": SEND, "completion": completion, "expected": send()});
        assert_eq!(score_row(&catalog(), &row).unwrap()["semantic_ok"], true);
        let body = json!({"choices": [{"message": {"content": completion}}]}).to_string();
        assert_eq!(reply_from_response(&body).unwrap(), send().to_string());
    }

    #[test]
    fn render_prompt_is_the_runtime_prompt_and_request() {
        let catalog = catalog();
        let out = render_row(
            &catalog,
            LinguistOutput::Full,
            &json!({"utterance": "  Mäud di bi Lea \n"}),
        )
        .unwrap();
        let (system, user) = catalog.render_prompt("Mäud di bi Lea", None).unwrap();
        assert_eq!(out["utterance"], "Mäud di bi Lea");
        assert_eq!(out["system"], SYSTEM_PROMPT);
        assert_eq!(out["user"], user);
        assert_eq!(out["request"], chat_request(&system, &user));
        assert_eq!(out["request"]["max_tokens"], 320);
        let subset = render_row(
            &catalog,
            LinguistOutput::Full,
            &json!({"utterance": "hi", "intent_ids": ["timer.set", "task.note"]}),
        )
        .unwrap();
        assert_eq!(
            subset["user"],
            catalog
                .render_prompt("hi", Some(&["timer.set", "task.note"]))
                .unwrap()
                .1
        );
        assert!(render_row(&catalog, LinguistOutput::Full, &json!({"utterance": ""})).is_err());
        assert!(render_row(
            &catalog,
            LinguistOutput::Full,
            &json!({"utterance": "hi", "intent_ids": ["x.unknown"]})
        )
        .is_err());
    }

    #[test]
    fn a_bad_row_or_expectation_fails_the_run_after_every_row() {
        let input = format!(
            "{}\nnot json\n{}\n",
            json!({"utterance": SEND, "completion": send().to_string(), "expected": send()}),
            json!({"utterance": SEND, "completion": "{}", "expected": {"intent": "x.unknown", "slots": {}}})
        );
        let mut out = Vec::new();
        let bad = run(
            &catalog(),
            Mode::Score,
            LinguistOutput::Full,
            None,
            input.as_bytes(),
            &mut out,
        )
        .unwrap();
        assert_eq!(bad, 2);
        let lines: Vec<Value> = String::from_utf8(out)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0]["core_accepts"], true);
        assert!(lines[1]["error"].as_str().unwrap().starts_with("line 2:"));
        assert!(lines[2]["error"]
            .as_str()
            .unwrap()
            .contains("unknown intent"));
    }

    /// Serve one reply on a private socket; the scored row and the raw request.
    fn serve_once(output: &str, reply: String) -> (Value, String) {
        use std::io::Read;
        use std::os::unix::net::UnixListener;
        let dir = std::env::temp_dir().join(format!(
            "vaikor-linguist-eval-{}-{output}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        // Approval tests set the process-wide umask to 0117 while they bind; set the mode
        // explicitly so this directory stays searchable whatever umask is current.
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let socket = dir.join("linguist.sock");
        let _ = std::fs::remove_file(&socket);
        let listener = UnixListener::bind(&socket).unwrap();
        let reply = json!({"choices": [{"message": {"content": reply}}]}).to_string();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut buf = [0u8; 65536];
            loop {
                let n = stream.read(&mut buf).unwrap();
                request.extend_from_slice(&buf[..n]);
                let text = String::from_utf8_lossy(&request);
                if let Some((head, body)) = text.split_once("\r\n\r\n") {
                    let length: usize = head
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length: "))
                        .unwrap()
                        .parse()
                        .unwrap();
                    if body.len() >= length {
                        break;
                    }
                }
            }
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{reply}",
                reply.len()
            );
            stream.write_all(response.as_bytes()).unwrap();
            String::from_utf8(request).unwrap()
        });
        let uid = unsafe { libc::geteuid() };
        let config = json!({"model": {"endpoint": format!("unix:{}", socket.display()),
            "uid": uid, "output": output}});
        let model = LocalLinguist::from_config(&config).unwrap().unwrap();
        let out = evaluate_row(
            &catalog(),
            &model,
            &json!({"utterance": SEND, "expected": send()}),
        )
        .unwrap();
        let request = server.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        (out, request.split_once("\r\n\r\n").unwrap().1.to_string())
    }

    #[test]
    fn serve_mode_sends_the_runtime_request_to_the_model_endpoint() {
        let (out, body) = serve_once("full", send().to_string());
        let catalog = catalog();
        assert_eq!(out["semantic_ok"], true, "{out}");
        assert_eq!(out["completion"], send().to_string());
        let body: Value = serde_json::from_str(&body).unwrap();
        let (system, user) = catalog.render_prompt(SEND, None).unwrap();
        assert_eq!(body, chat_request(&system, &user));
    }

    fn compact_send() -> Value {
        json!({"v": "0.2", "lang": "en", "intent": "messaging.send", "missing": [],
            "slots": {"recipient": "Nina", "topic": "the concert"}})
    }

    #[test]
    fn serve_mode_with_compact_output_sends_the_constrained_runtime_request() {
        let (out, body) = serve_once("compact", compact_send().to_string());
        let catalog = catalog();
        assert_eq!(out["semantic_ok"], true, "{out}");
        assert_eq!(out["corrections"], json!([]));
        let (system, user) = catalog
            .render_prompt_as(LinguistOutput::Compact, SEND, None)
            .unwrap();
        assert_eq!(system, SYSTEM_PROMPT_COMPACT);
        // Byte for byte what the runtime sends, schema member order included.
        assert_eq!(
            body,
            catalog.request_body(LinguistOutput::Compact, &system, &user)
        );
    }

    #[test]
    fn a_compact_reply_is_scored_like_a_full_one() {
        let out = score(SEND, compact_send(), send());
        assert_eq!(out["core_accepts"], true, "{out}");
        assert_eq!(out["corrections"], json!([]));
        assert_eq!(out["semantic_ok"], true);
        assert_eq!(out["legacy_effective"], true);
        assert_eq!(out["kept"], send());
        // The expectation may itself be a compact proposal (a v0.2 dataset).
        let out = score(SEND, compact_send(), compact_send());
        assert_eq!(out["semantic_ok"], true, "{out}");
        let mut extra = compact_send();
        extra["missing_slots"] = json!([]);
        let out = score(SEND, extra, send());
        assert_eq!(out["refusal"]["stage"], "envelope");
    }

    #[test]
    fn render_prompt_with_compact_output_is_the_constrained_runtime_request() {
        let catalog = catalog();
        let out = render_row(
            &catalog,
            LinguistOutput::Compact,
            &json!({"utterance": "Mäud di bi Lea"}),
        )
        .unwrap();
        let (system, user) = catalog
            .render_prompt_as(LinguistOutput::Compact, "Mäud di bi Lea", None)
            .unwrap();
        assert_eq!(out["system"], SYSTEM_PROMPT_COMPACT);
        assert_eq!(out["user"], user);
        let wire: Value =
            serde_json::from_str(&catalog.request_body(LinguistOutput::Compact, &system, &user))
                .unwrap();
        assert_eq!(out["request"], wire);
        assert_eq!(out["request"]["response_format"]["type"], "json_schema");
        let input = format!("{}\n", json!({"utterance": "hi"}));
        let mut lines = Vec::new();
        let bad = run(
            &catalog,
            Mode::RenderPrompt,
            LinguistOutput::Compact,
            None,
            input.as_bytes(),
            &mut lines,
        )
        .unwrap();
        assert_eq!(bad, 0);
        let line: Value = serde_json::from_slice(&lines).unwrap();
        assert_eq!(line["system"], SYSTEM_PROMPT_COMPACT);
    }

    #[test]
    fn an_unreachable_model_is_a_refusal_at_the_model_stage() {
        struct Down;
        impl LinguistModel for Down {
            fn propose(&self, _: &str, _: &str) -> Result<String, String> {
                Err("local model socket: connection refused".into())
            }
        }
        let out = evaluate_row(
            &catalog(),
            &Down,
            &json!({"utterance": SEND, "expected": send()}),
        )
        .unwrap();
        assert_eq!(out["refusal"]["stage"], "model");
        assert_eq!(out["core_accepts"], false);
    }
}
