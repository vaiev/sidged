// Copyright 2026 VAIEV
// SPDX-License-Identifier: Apache-2.0
//! Companion linguist (`Model -1`) Core contract: the intent catalog, the linguist prompt,
//! and verification of a linguist envelope (`spec/schemas/linguist-envelope.schema.json`).
//!
//! The linguist only proposes. The Core keeps `lang`, `intent` and `slots` after checking
//! them against the catalog and re-derives every other member (missing slots, clarification
//! question, canonical English intent, route, data classes). A disagreement is corrected
//! fail-closed and reported, never trusted. Structural violations (unknown members such as
//! `residency`, wrong types, an unknown language) refuse the proposal.
//!
//! A model may propose the full v0.1 envelope or the compact v0.2 proposal (0017 L3a: only
//! `v`, `lang`, `intent`, `slots`, `then`; `spec/schemas/linguist-proposal.schema.json`); both
//! derive the same envelope. `model.output: "compact"` asks for the compact form and constrains
//! decoding with `IntentCatalog::decoding_schema` (L8), which is no security boundary.
//!
//! `derive` is byte-for-byte the rules of `local-training/linguist.py`; both sides are pinned
//! by `tests/fixtures/linguist-prompt.json`. Training data and evaluation take their prompts
//! from `render_prompt` itself (`sidged linguist-eval render-prompt`, `crate::linguist_eval`).

use std::collections::BTreeSet;
use std::fmt;
use std::marker::PhantomData;

use serde::de::{Deserializer, MapAccess, Visitor};
use serde::ser::{SerializeMap, Serializer};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sidged_gateway::local_model::{model_endpoint, LocalModel, ModelEndpoint};

/// A complete, Core-verified intent from [`VerifiedIntent::to_canonical_intent`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CanonicalIntentEnvelope {
    pub v: String,
    pub source_locale: String,
    pub raw_utterance: String,
    pub canonical_english_intent: String,
    pub target_artifact_mime: String,
    pub required_capabilities: Vec<String>,
    pub data_classes: Vec<String>,
    pub residency: Vec<String>,
    pub clarification_needed: bool,
    pub clarification_question: Option<String>,
}

/// The generic intent catalog this Core ships with (validated by `spec/validate`).
pub const INTENT_CATALOG_JSON: &str = include_str!("../assets/intent-catalog.json");
pub const ROUTE_CLARIFY: &str = "clarify";
pub const ROUTES: [&str; 2] = ["edge-local", "swarm-worker"];
pub const ENVELOPE_KEYS: [&str; 10] = [
    "v",
    "lang",
    "intent",
    "slots",
    "missing_slots",
    "clarification_needed",
    "clarification_question_local",
    "canonical_intent_en",
    "suggested_route",
    "required_data_classes",
];
const MAX_SLOT_VALUE_CHARS: usize = 512;
pub const MAX_UTTERANCE_CHARS: usize = 1000;
const DEFAULT_ARTIFACT_MIME: &str = "application/vnd.sidged.artifact.solution+json";

pub const SYSTEM_PROMPT: &str = "You are Sidged Model -1, the companion linguist. Read one utterance in English, German or Swiss German \
and reply with exactly one JSON object and nothing else, with the keys v, lang, intent, slots, \
missing_slots, clarification_needed, clarification_question_local, canonical_intent_en, suggested_route, \
required_data_classes. lang is en, de or gsw. intent is one catalog intent, or null when none fits. \
slots holds only the values the utterance gives, in canonical English; names, quoted text, file names \
and slots described as verbatim stay as written. missing_slots lists the required slots (marked *) the \
utterance does not give. When a slot is missing or intent is null, ask one short question in the \
utterance language and use route clarify. When the utterance asks for one thing and then another, put \
the first in intent and slots and each further one, in order, in then as objects with intent and slots; \
only pairs listed under Compositions may follow each other, and a slot the earlier result gives is not \
missing. Your reply is a proposal: the Sidged Core re-checks it \
against the catalog. Never add residency, approval or grant fields.";

/// The instruction for the compact proposal (0017 L3a): the model gives only what the Core keeps.
pub const SYSTEM_PROMPT_COMPACT: &str = "You are Sidged Model -1, the companion linguist. Read one utterance in English, German or Swiss German \
and reply with exactly one JSON object and nothing else, with the keys v, lang, intent, missing, slots. v is 0.2. \
lang is en, de or gsw. intent is one catalog intent, or null when none fits. missing lists the required slots \
(marked *) the utterance does not give, before you write slots; it is empty when intent is null. slots holds \
only the values the utterance gives, never a slot listed in missing, in canonical English; names, quoted text, file names and slots described as verbatim \
stay as written. When the utterance asks for one thing and then another, put the first in intent and slots \
and each further one, in order, in then as objects with intent and slots; only pairs listed under \
Compositions may follow each other, and a slot the earlier result gives is left out. Your reply is a \
proposal: the Sidged Core re-checks it against the catalog and asks for what is missing. Never add other keys.";

/// The version of a compact proposal (0017 L3a); a full envelope is v0.1.
pub const PROPOSAL_V: &str = "0.2";
/// The members of a compact proposal, in order; `then` is the one optional member.
pub const PROPOSAL_KEYS: [&str; 5] = ["v", "lang", "intent", "missing", "slots"];

/// What the linguist is asked to emit: the full v0.1 envelope (run 8 and earlier) or the
/// compact v0.2 proposal under catalog-constrained decoding (0017 L3a, L8). The Core accepts
/// both whatever the setting; it decides the prompt and the request only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LinguistOutput {
    #[default]
    Full,
    Compact,
}

impl LinguistOutput {
    /// `model.output` of a node config: absent or `"full"`, or `"compact"`; anything else refuses.
    pub fn from_config(config: &Value) -> Result<Self, String> {
        match config.get("model").and_then(|m| m.get("output")) {
            None => Ok(Self::Full),
            Some(Value::String(name)) if name == "full" => Ok(Self::Full),
            Some(Value::String(name)) if name == "compact" => Ok(Self::Compact),
            Some(other) => Err(format!(
                "config model.output must be \"full\" or \"compact\", got {other}"
            )),
        }
    }

    pub fn system_prompt(self) -> &'static str {
        match self {
            Self::Full => SYSTEM_PROMPT,
            Self::Compact => SYSTEM_PROMPT_COMPACT,
        }
    }
}

/// A JSON value that keeps its member order when serialized. llama.cpp turns a JSON Schema
/// into a grammar in `properties` order, so the decoding schema must reach it in the order
/// the model is trained on; a `serde_json::Value` would sort the members.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
pub enum OrderedJson {
    Object(Ordered<OrderedJson>),
    Array(Vec<OrderedJson>),
    Scalar(Value),
}

impl OrderedJson {
    fn object(members: Vec<(&str, OrderedJson)>) -> Self {
        Self::Object(Ordered(
            members
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
        ))
    }

    fn scalar(value: Value) -> Self {
        Self::Scalar(value)
    }
}

/// A JSON object in document order. `serde_json` is built without `preserve_order`, so a
/// plain `Map` would sort the slots and change the prompt bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ordered<T>(pub Vec<(String, T)>);

impl<T> Default for Ordered<T> {
    fn default() -> Self {
        Self(Vec::new())
    }
}

impl<T> Ordered<T> {
    pub fn get(&self, key: &str) -> Option<&T> {
        self.0.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    pub fn contains_key(&self, key: &str) -> bool {
        self.get(key).is_some()
    }

    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.0.iter().map(|(k, _)| k.as_str())
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Ordered<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct OrderedVisitor<T>(PhantomData<T>);

        impl<'de, T: Deserialize<'de>> Visitor<'de> for OrderedVisitor<T> {
            type Value = Ordered<T>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a JSON object")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut entries: Vec<(String, T)> = Vec::new();
                while let Some((key, value)) = map.next_entry::<String, T>()? {
                    if entries.iter().any(|(k, _)| *k == key) {
                        return Err(serde::de::Error::custom(format!("duplicate key {key}")));
                    }
                    entries.push((key, value));
                }
                Ok(Ordered(entries))
            }
        }

        deserializer.deserialize_map(OrderedVisitor(PhantomData))
    }
}

impl<T: Serialize> Serialize for Ordered<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (key, value) in &self.0 {
            map.serialize_entry(key, value)?;
        }
        map.end()
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlotSpec {
    #[serde(rename = "type")]
    pub kind: String,
    pub description: String,
    #[serde(rename = "x-ask")]
    pub ask: Ordered<String>,
    /// The value is always copied from the utterance (a name, a file, quoted text), so the
    /// Core can check that it occurs there (0017 L7).
    #[serde(rename = "x-verbatim", default)]
    pub verbatim: bool,
}

/// The proposed slots the Core keeps for one intent (0017 L4, L7); dropped slots are
/// reported with `prefix` (`then[0].` for a follow-up). A non-string value refuses the reply.
fn keep_slots(
    entry: &IntentEntry,
    given: &serde_json::Map<String, Value>,
    utterance: Option<&str>,
    prefix: &str,
    corrections: &mut Vec<String>,
) -> Result<Ordered<String>, String> {
    let mut slots = Ordered::default();
    for (name, value) in given {
        let Some(text) = value.as_str() else {
            return Err(format!("{prefix}slot {name} is not a string"));
        };
        let spec = entry.slots_schema.properties.get(name);
        if spec.is_none() {
            corrections.push(format!("{prefix}slot-unknown:{name}"));
        } else if text.trim().is_empty()
            || text.chars().count() > MAX_SLOT_VALUE_CHARS
            || text.chars().any(char::is_control)
        {
            corrections.push(format!("{prefix}slot-value-refused:{name}"));
        } else if spec.is_some_and(|s| s.verbatim) && utterance.is_some_and(|u| !grounded(u, text))
        {
            corrections.push(format!("{prefix}slot-ungrounded:{name}"));
        } else {
            slots.0.push((name.clone(), text.to_string()));
        }
    }
    Ok(slots)
}

/// Whether a verbatim slot value occurs in the utterance (case and spacing ignored).
fn grounded(utterance: &str, value: &str) -> bool {
    let norm = |text: &str| {
        text.to_lowercase()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    };
    let value = norm(
        value
            .trim()
            .trim_matches(|c| c == '"' || c == '\'' || c == '«' || c == '»'),
    );
    !value.is_empty() && norm(utterance).contains(&value)
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlotsSchema {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(rename = "additionalProperties")]
    pub additional_properties: bool,
    pub properties: Ordered<SlotSpec>,
    pub required: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentEntry {
    pub intent: String,
    pub title: String,
    pub canonical_en: String,
    pub slots_schema: SlotsSchema,
    pub capabilities: Vec<String>,
    pub data_classes: Vec<String>,
    #[serde(default)]
    pub artifact_mime: Option<String>,
    pub route: String,
    /// Declarative SDG-L3 plan instantiated from the verified slots (`crate::intent_plan`).
    #[serde(default)]
    pub plan: Option<PlanTemplate>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanTemplate {
    pub steps: Vec<PlanTemplateStep>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanTemplateStep {
    pub id: String,
    pub capability: String,
    #[serde(default)]
    pub approval: bool,
    pub args: Ordered<TemplateArg>,
}

/// A plan argument in the catalog: a verified slot, the canonical intent, or an earlier step
/// (its whole output, or the member `field` of it, 0003 R4a).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "RawTemplateArg")]
pub enum TemplateArg {
    Slot(String),
    Intent(String),
    Ref { step: String, field: Option<String> },
}

/// The catalog form of [`TemplateArg`]: exactly one of `slot`, `intent`, `ref`, and `field`
/// only next to `ref`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTemplateArg {
    slot: Option<String>,
    intent: Option<String>,
    #[serde(rename = "ref")]
    step: Option<String>,
    field: Option<String>,
}

impl TryFrom<RawTemplateArg> for TemplateArg {
    type Error = &'static str;

    fn try_from(raw: RawTemplateArg) -> Result<Self, Self::Error> {
        match raw {
            RawTemplateArg {
                slot: Some(slot),
                intent: None,
                step: None,
                field: None,
            } => Ok(Self::Slot(slot)),
            RawTemplateArg {
                slot: None,
                intent: Some(intent),
                step: None,
                field: None,
            } => Ok(Self::Intent(intent)),
            RawTemplateArg {
                slot: None,
                intent: None,
                step: Some(step),
                field,
            } => Ok(Self::Ref { step, field }),
            _ => Err("a plan argument is one of slot, intent or ref (with an optional field)"),
        }
    }
}

/// A declared composition (0017 §2c): `then` may follow `first` in one utterance.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Composition {
    pub first: String,
    pub then: String,
    /// Required slots of `then` the earlier result provides (K3).
    #[serde(default)]
    pub satisfies: Vec<String>,
    /// Steps of `then`'s plan replaced by steps of `first`'s plan (K4).
    #[serde(default)]
    pub replaces: Ordered<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentCatalog {
    pub v: String,
    pub locales: Vec<String>,
    pub unknown_intent_ask: Ordered<String>,
    pub intents: Vec<IntentEntry>,
    #[serde(default)]
    pub compositions: Vec<Composition>,
}

/// One follow-up intent of a composition, as the Core derives it (0017 K1, K3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FollowUp {
    pub intent: String,
    pub slots: Ordered<String>,
    pub missing_slots: Vec<String>,
    pub canonical_intent_en: String,
}

/// The most follow-ups one utterance may chain (K1).
pub const MAX_FOLLOW_UPS: usize = 2;
const FOLLOW_UP_KEYS: [&str; 4] = ["intent", "slots", "missing_slots", "canonical_intent_en"];

/// One linguist envelope, serialized in the member order the model generates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LinguistEnvelope {
    pub v: String,
    pub lang: String,
    pub intent: Option<String>,
    pub slots: Ordered<String>,
    pub missing_slots: Vec<String>,
    pub clarification_needed: bool,
    pub clarification_question_local: Option<String>,
    pub canonical_intent_en: Option<String>,
    pub suggested_route: String,
    pub required_data_classes: Vec<String>,
    /// Follow-ups of a composition (§2c); absent from a single-intent envelope.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub then: Vec<FollowUp>,
}

/// The envelope the Core accepts, plus every correction it made to the proposal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedIntent {
    pub envelope: LinguistEnvelope,
    pub corrections: Vec<String>,
}

/// `{slot}` placeholders of a template, as (start, end, name) byte ranges.
fn placeholders(template: &str) -> Vec<(usize, usize, &str)> {
    let bytes = template.as_bytes();
    let mut found = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'{' {
            let mut j = i + 1;
            while j < bytes.len()
                && (bytes[j].is_ascii_lowercase() || bytes[j].is_ascii_digit() || bytes[j] == b'_')
            {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'}' && j > i + 1 && bytes[i + 1].is_ascii_lowercase()
            {
                found.push((i, j + 1, &template[i + 1..j]));
                i = j + 1;
                continue;
            }
        }
        i += 1;
    }
    found
}

impl IntentEntry {
    fn catalog_line(&self) -> String {
        let schema = &self.slots_schema;
        let slots: Vec<String> = schema
            .properties
            .0
            .iter()
            .map(|(name, spec)| {
                let star = if schema.required.contains(name) {
                    "*"
                } else {
                    ""
                };
                format!("{name}{star}: {}", spec.description)
            })
            .collect();
        let classes = if self.data_classes.is_empty() {
            "-".to_string()
        } else {
            self.data_classes.join(", ")
        };
        format!(
            "- {} | {} | route {} | classes {} | template {} | slots {}",
            self.intent,
            self.title,
            self.route,
            classes,
            self.canonical_en,
            slots.join("; ")
        )
    }

    /// Fill the template; a missing slot reads `<slot>`; optional extras follow in parentheses.
    fn canonical_text(&self, slots: &Ordered<String>) -> String {
        let marks = placeholders(&self.canonical_en);
        let mut text = String::new();
        let mut last = 0;
        for (start, end, name) in &marks {
            text.push_str(&self.canonical_en[last..*start]);
            match slots.get(name) {
                Some(value) => text.push_str(value),
                None => text.push_str(&format!("<{name}>")),
            }
            last = *end;
        }
        text.push_str(&self.canonical_en[last..]);
        let used: BTreeSet<&str> = marks.iter().map(|(_, _, name)| *name).collect();
        let extras: Vec<String> = self
            .slots_schema
            .properties
            .keys()
            .filter(|name| !used.contains(name))
            .filter_map(|name| slots.get(name).map(|value| format!("{name}: {value}")))
            .collect();
        if !extras.is_empty() {
            text.push_str(&format!(" ({})", extras.join("; ")));
        }
        text.split_whitespace().collect::<Vec<_>>().join(" ")
    }
}

impl IntentCatalog {
    /// The catalog compiled into this Core.
    pub fn builtin() -> Result<Self, String> {
        Self::parse(INTENT_CATALOG_JSON)
    }

    /// Parse and check a catalog (the cross-member rules of `intent-catalog.schema.json`).
    pub fn parse(text: &str) -> Result<Self, String> {
        let catalog: Self =
            serde_json::from_str(text).map_err(|e| format!("intent-catalog-invalid: {e}"))?;
        catalog.check()?;
        Ok(catalog)
    }

    fn check(&self) -> Result<(), String> {
        let fail = |what: String| Err(format!("intent-catalog-invalid: {what}"));
        if self.v != "0.1" {
            return fail(format!("version {}", self.v));
        }
        if self.locales.is_empty() || self.intents.is_empty() {
            return fail("no locales or no intents".into());
        }
        let complete = |texts: &Ordered<String>, place: &str| -> Result<(), String> {
            for locale in &self.locales {
                if texts.get(locale).is_none_or(|text| text.is_empty()) {
                    return fail(format!("{place} has no text for locale {locale}"));
                }
            }
            if let Some(extra) = texts.keys().find(|k| !self.locales.iter().any(|l| l == k)) {
                return fail(format!("{place} uses undeclared locale {extra}"));
            }
            Ok(())
        };
        complete(&self.unknown_intent_ask, "unknown_intent_ask")?;
        let mut seen = BTreeSet::new();
        for entry in &self.intents {
            let name = &entry.intent;
            if !seen.insert(name.as_str()) {
                return fail(format!("duplicate intent {name}"));
            }
            if !ROUTES.contains(&entry.route.as_str()) {
                return fail(format!("{name}: unknown route {}", entry.route));
            }
            let schema = &entry.slots_schema;
            if schema.kind != "object"
                || schema.additional_properties
                || schema.properties.is_empty()
            {
                return fail(format!("{name}: slots_schema must be a closed object"));
            }
            for slot in &schema.required {
                if !schema.properties.contains_key(slot) {
                    return fail(format!("{name}: required slot {slot} is not declared"));
                }
            }
            for (_, _, slot) in placeholders(&entry.canonical_en) {
                if !schema.properties.contains_key(slot) {
                    return fail(format!("{name}: canonical_en names undeclared slot {slot}"));
                }
            }
            for (slot, spec) in &schema.properties.0 {
                if spec.kind != "string" {
                    return fail(format!("{name}.{slot}: slots are strings"));
                }
                complete(&spec.ask, &format!("{name}.{slot}.x-ask"))?;
            }
            if let Some(plan) = &entry.plan {
                let mut earlier: Vec<&str> = Vec::new();
                for step in &plan.steps {
                    if earlier.contains(&step.id.as_str()) {
                        return fail(format!("{name}: plan step {} is repeated", step.id));
                    }
                    if !entry.capabilities.contains(&step.capability) {
                        return fail(format!(
                            "{name}: plan step {} uses {}, which the intent does not name",
                            step.id, step.capability
                        ));
                    }
                    for (arg, value) in &step.args.0 {
                        let ok = match value {
                            TemplateArg::Slot(slot) => schema.properties.contains_key(slot),
                            TemplateArg::Intent(what) => what == "canonical",
                            TemplateArg::Ref { step, .. } => earlier.contains(&step.as_str()),
                        };
                        if !ok {
                            return fail(format!(
                                "{name}: plan step {} argument {arg} is unresolvable",
                                step.id
                            ));
                        }
                    }
                    earlier.push(&step.id);
                }
            }
            if let Some(capability) = entry
                .capabilities
                .iter()
                .find(|c| !c.starts_with("urn:sidged:capability:"))
            {
                return fail(format!(
                    "{name}: capability {capability} is not a sidged URN"
                ));
            }
        }
        for c in &self.compositions {
            let pair = format!("composition {} -> {}", c.first, c.then);
            let (Some(first), Some(then)) = (self.intent(&c.first), self.intent(&c.then)) else {
                return fail(format!("{pair} names an unknown intent"));
            };
            if self
                .compositions
                .iter()
                .filter(|o| o.first == c.first && o.then == c.then)
                .count()
                > 1
            {
                return fail(format!("{pair} is declared twice"));
            }
            if let Some(slot) = c
                .satisfies
                .iter()
                .find(|s| !then.slots_schema.required.contains(s))
            {
                return fail(format!(
                    "{pair} satisfies {slot}, not a required slot of {}",
                    c.then
                ));
            }
            let steps = |entry: &IntentEntry| -> Vec<String> {
                entry
                    .plan
                    .iter()
                    .flat_map(|p| p.steps.iter().map(|s| s.id.clone()))
                    .collect()
            };
            for (replaced, by) in &c.replaces.0 {
                if !steps(then).contains(replaced) || !steps(first).contains(by) {
                    return fail(format!(
                        "{pair} replaces {replaced} by {by}, not plan steps"
                    ));
                }
            }
        }
        Ok(())
    }

    pub fn intent(&self, id: &str) -> Option<&IntentEntry> {
        self.intents.iter().find(|entry| entry.intent == id)
    }

    /// (system, user) prompt for one utterance; `intent_ids` limits and orders the catalog.
    pub fn render_prompt(
        &self,
        utterance: &str,
        intent_ids: Option<&[&str]>,
    ) -> Result<(String, String), String> {
        self.render_prompt_as(LinguistOutput::Full, utterance, intent_ids)
    }

    /// As `render_prompt`, with the instruction for `output`; the user prompt is the same.
    pub fn render_prompt_as(
        &self,
        output: LinguistOutput,
        utterance: &str,
        intent_ids: Option<&[&str]>,
    ) -> Result<(String, String), String> {
        let lines: Vec<String> = match intent_ids {
            None => self.intents.iter().map(IntentEntry::catalog_line).collect(),
            Some(ids) => ids
                .iter()
                .map(|id| {
                    self.intent(id)
                        .map(IntentEntry::catalog_line)
                        .ok_or_else(|| format!("unknown intent {id}"))
                })
                .collect::<Result<_, _>>()?,
        };
        // K6: a composition is listed when both of its intents are shown.
        let shown: Vec<&str> = match intent_ids {
            None => self.intents.iter().map(|e| e.intent.as_str()).collect(),
            Some(ids) => ids.to_vec(),
        };
        let pairs: Vec<String> = self
            .compositions
            .iter()
            .filter(|c| shown.contains(&c.first.as_str()) && shown.contains(&c.then.as_str()))
            .map(|c| {
                let mut line = format!("- {} then {}", c.first, c.then);
                if !c.satisfies.is_empty() {
                    line.push_str(&format!(
                        " | the earlier result gives {}",
                        c.satisfies.join(", ")
                    ));
                }
                line
            })
            .collect();
        let block = if pairs.is_empty() {
            String::new()
        } else {
            format!("\nCompositions:\n{}", pairs.join("\n"))
        };
        Ok((
            output.system_prompt().to_string(),
            format!(
                "Catalog:\n{}{block}\nUtterance: {utterance}",
                lines.join("\n")
            ),
        ))
    }

    /// The JSON Schema that constrains decoding of a compact proposal (0017 L8): per intent,
    /// one branch for each subset of its required slots the proposal declares `missing`, with
    /// those slots absent and the other required ones present, and the compositions declared
    /// from it; and one branch for `intent: null`. Not a security boundary: every proposal is
    /// still verified.
    pub fn decoding_schema(&self) -> OrderedJson {
        let base = |intent: OrderedJson, missing: &[&String], slots: OrderedJson| {
            vec![
                ("v", OrderedJson::scalar(json!({"const": PROPOSAL_V}))),
                ("lang", OrderedJson::scalar(json!({"enum": self.locales}))),
                ("intent", intent),
                ("missing", OrderedJson::scalar(json!({"const": missing}))),
                ("slots", slots),
            ]
        };
        let branch = |properties: Vec<(&str, OrderedJson)>| {
            OrderedJson::object(vec![
                ("type", OrderedJson::scalar(json!("object"))),
                ("properties", OrderedJson::object(properties)),
                ("required", OrderedJson::scalar(json!(PROPOSAL_KEYS))),
                ("additionalProperties", OrderedJson::scalar(json!(false))),
            ])
        };
        let mut branches: Vec<OrderedJson> = Vec::new();
        for entry in &self.intents {
            let chains: Vec<OrderedJson> = self
                .chains_from(&entry.intent)
                .into_iter()
                .map(|chain| {
                    let items: Vec<OrderedJson> = chain
                        .iter()
                        .map(|next| {
                            OrderedJson::object(vec![
                                ("type", OrderedJson::scalar(json!("object"))),
                                (
                                    "properties",
                                    OrderedJson::object(vec![
                                        (
                                            "intent",
                                            OrderedJson::scalar(json!({"const": next.intent})),
                                        ),
                                        ("slots", Self::slots_schema_of(next)),
                                    ]),
                                ),
                                ("required", OrderedJson::scalar(json!(["intent", "slots"]))),
                                ("additionalProperties", OrderedJson::scalar(json!(false))),
                            ])
                        })
                        .collect();
                    OrderedJson::object(vec![
                        ("type", OrderedJson::scalar(json!("array"))),
                        ("prefixItems", OrderedJson::Array(items)),
                        ("minItems", OrderedJson::scalar(json!(chain.len()))),
                        ("maxItems", OrderedJson::scalar(json!(chain.len()))),
                    ])
                })
                .collect();
            let then = match chains.len() {
                0 => None,
                1 => chains.into_iter().next(),
                _ => Some(OrderedJson::object(vec![(
                    "oneOf",
                    OrderedJson::Array(chains),
                )])),
            };
            let required = &entry.slots_schema.required;
            for subset in 0..1usize << required.len() {
                let missing: Vec<&String> = (0..required.len())
                    .filter(|i| subset & (1 << i) != 0)
                    .map(|i| &required[i])
                    .collect();
                let mut properties = base(
                    OrderedJson::scalar(json!({"const": entry.intent})),
                    &missing,
                    Self::slots_schema_without(entry, &missing),
                );
                if let Some(then) = &then {
                    properties.push(("then", then.clone()));
                }
                branches.push(branch(properties));
            }
        }
        branches.push(branch(base(
            OrderedJson::scalar(json!({"type": "null"})),
            &[],
            OrderedJson::scalar(
                json!({"type": "object", "properties": {}, "additionalProperties": false}),
            ),
        )));
        OrderedJson::object(vec![("oneOf", OrderedJson::Array(branches))])
    }

    /// An intent's slots for decoding when the proposal declares `missing`: the others in
    /// catalog order, each required one that is not missing required (llama.cpp writes the
    /// required members first, then the optional ones, each in catalog order).
    fn slots_schema_without(entry: &IntentEntry, missing: &[&String]) -> OrderedJson {
        let slot = json!({"type": "string", "minLength": 1, "maxLength": MAX_SLOT_VALUE_CHARS});
        let names: Vec<&str> = entry
            .slots_schema
            .properties
            .keys()
            .filter(|name| !missing.iter().any(|m| m == name))
            .collect();
        let required: Vec<&str> = names
            .iter()
            .copied()
            .filter(|name| entry.slots_schema.required.iter().any(|r| r == name))
            .collect();
        let mut members = vec![
            ("type", OrderedJson::scalar(json!("object"))),
            (
                "properties",
                OrderedJson::Object(Ordered(
                    names
                        .iter()
                        .map(|name| (name.to_string(), OrderedJson::scalar(slot.clone())))
                        .collect(),
                )),
            ),
        ];
        if !required.is_empty() {
            members.push(("required", OrderedJson::scalar(json!(required))));
        }
        members.push(("additionalProperties", OrderedJson::scalar(json!(false))));
        OrderedJson::object(members)
    }

    /// A follow-up's slots for decoding, in catalog order: strings of 1 to 512 characters, none
    /// required (a follow-up's slot may come from the earlier result, K3).
    fn slots_schema_of(entry: &IntentEntry) -> OrderedJson {
        let slot = json!({"type": "string", "minLength": 1, "maxLength": MAX_SLOT_VALUE_CHARS});
        OrderedJson::object(vec![
            ("type", OrderedJson::scalar(json!("object"))),
            (
                "properties",
                OrderedJson::Object(Ordered(
                    entry
                        .slots_schema
                        .properties
                        .keys()
                        .map(|name| (name.to_string(), OrderedJson::scalar(slot.clone())))
                        .collect(),
                )),
            ),
            ("additionalProperties", OrderedJson::scalar(json!(false))),
        ])
    }

    /// Every declared follow-up chain after `first` (K1, K2): one or two intents, each pair declared.
    fn chains_from(&self, first: &str) -> Vec<Vec<&IntentEntry>> {
        let after = |id: &str| -> Vec<&IntentEntry> {
            self.compositions
                .iter()
                .filter(|c| c.first == id)
                .filter_map(|c| self.intent(&c.then))
                .collect()
        };
        let mut chains = Vec::new();
        for next in after(first) {
            chains.push(vec![next]);
            for last in after(&next.intent) {
                chains.push(vec![next, last]);
            }
        }
        chains
    }

    /// The request body for (system, user): `chat_request`, plus the decoding schema as
    /// llama-server's `response_format` for compact output.
    pub fn request_body(&self, output: LinguistOutput, system: &str, user: &str) -> String {
        match output {
            LinguistOutput::Full => chat_request(system, user).to_string(),
            LinguistOutput::Compact => constrained_request(system, user, &self.decoding_schema()),
        }
    }

    /// The envelope the Core accepts for (lang, intent, slots).
    pub fn derive(
        &self,
        lang: &str,
        intent: Option<&str>,
        slots: &Ordered<String>,
    ) -> Result<LinguistEnvelope, String> {
        if !self.locales.iter().any(|l| l == lang) {
            return Err(format!("unknown locale {lang}"));
        }
        let Some(intent) = intent else {
            return Ok(LinguistEnvelope {
                v: "0.1".into(),
                lang: lang.into(),
                intent: None,
                slots: Ordered::default(),
                missing_slots: Vec::new(),
                clarification_needed: true,
                clarification_question_local: self.unknown_intent_ask.get(lang).cloned(),
                canonical_intent_en: None,
                suggested_route: ROUTE_CLARIFY.into(),
                required_data_classes: Vec::new(),
                then: Vec::new(),
            });
        };
        let entry = self
            .intent(intent)
            .ok_or_else(|| format!("unknown intent {intent}"))?;
        let properties = &entry.slots_schema.properties;
        if let Some(unknown) = slots.keys().find(|name| !properties.contains_key(name)) {
            return Err(format!("{intent}: unknown slot {unknown}"));
        }
        let ordered = Ordered(
            properties
                .keys()
                .filter_map(|name| slots.get(name).map(|v| (name.to_string(), v.clone())))
                .collect(),
        );
        let missing: Vec<String> = entry
            .slots_schema
            .required
            .iter()
            .filter(|name| !ordered.contains_key(name))
            .cloned()
            .collect();
        let question = missing
            .first()
            .and_then(|slot| properties.get(slot))
            .and_then(|spec| spec.ask.get(lang).cloned());
        Ok(LinguistEnvelope {
            v: "0.1".into(),
            lang: lang.into(),
            intent: Some(intent.into()),
            canonical_intent_en: Some(entry.canonical_text(&ordered)),
            slots: ordered,
            clarification_needed: !missing.is_empty(),
            suggested_route: if missing.is_empty() {
                entry.route.clone()
            } else {
                ROUTE_CLARIFY.into()
            },
            missing_slots: missing,
            clarification_question_local: question,
            required_data_classes: entry.data_classes.clone(),
            then: Vec::new(),
        })
    }

    /// The declared composition of `first` followed by `then`, if any (K2).
    pub fn composition(&self, first: &str, then: &str) -> Option<&Composition> {
        self.compositions
            .iter()
            .find(|c| c.first == first && c.then == then)
    }

    /// The envelope for a composition: the first intent as `derive`, then each follow-up with
    /// the slots its predecessor satisfies (K3). Pairs must be declared.
    pub fn derive_with_then(
        &self,
        lang: &str,
        intent: Option<&str>,
        slots: &Ordered<String>,
        then: &[(String, Ordered<String>)],
    ) -> Result<LinguistEnvelope, String> {
        let mut envelope = self.derive(lang, intent, slots)?;
        let Some(mut previous) = intent.map(str::to_string) else {
            return Ok(envelope);
        };
        for (next, given) in then.iter().take(MAX_FOLLOW_UPS) {
            let composition = self
                .composition(&previous, next)
                .ok_or_else(|| format!("composition {previous} -> {next} is not declared"))?;
            let entry = self
                .intent(next)
                .ok_or_else(|| format!("unknown intent {next}"))?;
            let properties = &entry.slots_schema.properties;
            if let Some(unknown) = given.keys().find(|name| !properties.contains_key(name)) {
                return Err(format!("{next}: unknown slot {unknown}"));
            }
            let ordered = Ordered(
                properties
                    .keys()
                    .filter_map(|name| given.get(name).map(|v| (name.to_string(), v.clone())))
                    .collect(),
            );
            let missing: Vec<String> = entry
                .slots_schema
                .required
                .iter()
                .filter(|name| !ordered.contains_key(name) && !composition.satisfies.contains(name))
                .cloned()
                .collect();
            if envelope.missing_slots.is_empty()
                && envelope.then.iter().all(|f| f.missing_slots.is_empty())
            {
                if let Some(slot) = missing.first() {
                    envelope.clarification_question_local = properties
                        .get(slot)
                        .and_then(|spec| spec.ask.get(lang).cloned());
                }
            }
            if !missing.is_empty() {
                envelope.clarification_needed = true;
                envelope.suggested_route = ROUTE_CLARIFY.into();
            }
            for class in &entry.data_classes {
                if !envelope.required_data_classes.contains(class) {
                    envelope.required_data_classes.push(class.clone());
                }
            }
            // A slot the earlier result satisfies reads as that result in the canonical text.
            let mut shown = ordered.clone();
            for slot in &composition.satisfies {
                if !shown.contains_key(slot) {
                    shown.0.push((slot.clone(), "the previous result".into()));
                }
            }
            envelope.then.push(FollowUp {
                intent: next.clone(),
                canonical_intent_en: entry.canonical_text(&shown),
                slots: ordered,
                missing_slots: missing,
            });
            previous = next.clone();
        }
        Ok(envelope)
    }

    /// Check a raw linguist reply against the catalog and return the envelope the Core keeps.
    pub fn verify_proposal(&self, raw: &str) -> Result<VerifiedIntent, String> {
        self.verify_reply(None, raw)
    }

    /// As `verify_proposal`, and verbatim slots must occur in the utterance (0017 L7).
    pub fn verify_proposal_for(
        &self,
        utterance: &str,
        raw: &str,
    ) -> Result<VerifiedIntent, String> {
        self.verify_reply(Some(utterance), raw)
    }

    fn verify_reply(&self, utterance: Option<&str>, raw: &str) -> Result<VerifiedIntent, String> {
        let refuse = |what: String| Err(format!("linguist-envelope-invalid: {what}"));
        let proposal: Value = match serde_json::from_str(raw.trim()) {
            Ok(value) => value,
            Err(e) => return refuse(format!("not JSON: {e}")),
        };
        let Some(object) = proposal.as_object() else {
            return refuse("not a JSON object".into());
        };
        // L3a: `v` "0.2" is the compact proposal; every other proposal is a full envelope.
        let compact = object.get("v").and_then(Value::as_str) == Some(PROPOSAL_V);
        let (members, follow_up_members): (&[&str], &[&str]) = if compact {
            (&PROPOSAL_KEYS, &FOLLOW_UP_KEYS[..2])
        } else {
            (&ENVELOPE_KEYS, &FOLLOW_UP_KEYS)
        };
        if let Some(extra) = object
            .keys()
            .find(|k| !members.contains(&k.as_str()) && *k != "then")
        {
            return refuse(format!("unexpected member {extra}"));
        }
        if let Some(absent) = members.iter().find(|k| !object.contains_key(**k)) {
            return refuse(format!("missing member {absent}"));
        }
        let Some(lang) = object["lang"].as_str() else {
            return refuse("lang is not a string".into());
        };
        if !self.locales.iter().any(|l| l == lang) {
            return refuse(format!("unknown locale {lang}"));
        }
        let mut corrections = Vec::new();
        let intent = match &object["intent"] {
            Value::Null => None,
            Value::String(id) if self.intent(id).is_some() => Some(id.as_str()),
            Value::String(id) => {
                corrections.push(format!("intent-unknown:{id}"));
                None
            }
            _ => return refuse("intent is neither a string nor null".into()),
        };
        let Some(given) = object["slots"].as_object() else {
            return refuse("slots is not an object".into());
        };
        // L3a: the compact proposal commits to `missing` before its slots; a slot it declares
        // missing and still gives is dropped, never kept.
        let mut declared_missing: Vec<String> = Vec::new();
        let mut trimmed;
        let given = if compact {
            declared_missing = match object["missing"].as_array().and_then(|names| {
                names
                    .iter()
                    .map(|n| n.as_str().map(str::to_string))
                    .collect()
            }) {
                Some(names) => names,
                None => return refuse("missing is not an array of slot names".into()),
            };
            trimmed = given.clone();
            for name in &declared_missing {
                if trimmed.remove(name).is_some() {
                    corrections.push(format!("slot-declared-missing:{name}"));
                }
            }
            &trimmed
        } else {
            given
        };
        let mut slots = Ordered::default();
        if let Some(entry) = intent.and_then(|id| self.intent(id)) {
            slots = match keep_slots(entry, given, utterance, "", &mut corrections) {
                Ok(kept) => kept,
                Err(problem) => return refuse(problem),
            };
        } else if !given.is_empty() {
            corrections.push("slots-without-intent".into());
        }
        // §2c: follow-ups, verified like the first intent and chained only where declared.
        let mut then = Vec::new();
        if let Some(proposed) = object.get("then") {
            let Some(items) = proposed.as_array().filter(|a| a.len() <= MAX_FOLLOW_UPS) else {
                return refuse(format!("then is not an array of at most {MAX_FOLLOW_UPS}"));
            };
            // Every follow-up's members are checked before any is dropped as undeclared.
            let mut follow_ups = Vec::with_capacity(items.len());
            for (index, item) in items.iter().enumerate() {
                let Some(fields) = item.as_object() else {
                    return refuse(format!("then[{index}] is not an object"));
                };
                if let Some(extra) = fields
                    .keys()
                    .find(|k| !follow_up_members.contains(&k.as_str()))
                {
                    return refuse(format!("then[{index}] has unexpected member {extra}"));
                }
                follow_ups.push(fields);
            }
            let mut previous = intent.map(str::to_string);
            for (index, fields) in follow_ups.into_iter().enumerate() {
                let (Some(next), Some(given)) = (
                    fields.get("intent").and_then(Value::as_str),
                    fields.get("slots").and_then(Value::as_object),
                ) else {
                    corrections.push("composition-undeclared".into());
                    break;
                };
                let declared = previous
                    .as_deref()
                    .is_some_and(|p| self.composition(p, next).is_some());
                let Some(entry) = self.intent(next).filter(|_| declared) else {
                    corrections.push("composition-undeclared".into());
                    break;
                };
                let prefix = format!("then[{index}].");
                let kept = match keep_slots(entry, given, utterance, &prefix, &mut corrections) {
                    Ok(kept) => kept,
                    Err(problem) => return refuse(problem),
                };
                then.push((next.to_string(), kept));
                previous = Some(next.to_string());
            }
        }
        let envelope = self.derive_with_then(lang, intent, &slots, &then)?;
        if compact {
            // The only derived member it proposed is `missing`; the Core's derivation wins.
            if envelope.missing_slots != declared_missing {
                corrections.push("missing-corrected".into());
            }
            return Ok(VerifiedIntent {
                envelope,
                corrections,
            });
        }
        let derived = serde_json::to_value(&envelope).map_err(|e| e.to_string())?;
        for (index, follow_up) in derived["then"].as_array().into_iter().flatten().enumerate() {
            let proposed = &object["then"][index];
            for key in ["missing_slots", "canonical_intent_en"] {
                if proposed
                    .get(key)
                    .is_some_and(|value| *value != follow_up[key])
                {
                    corrections.push(format!("then[{index}].{key}-corrected"));
                }
            }
        }
        for key in &ENVELOPE_KEYS[4..] {
            if object[*key] != derived[*key] {
                corrections.push(format!("{key}-corrected"));
            }
        }
        if object["v"] != derived["v"] {
            corrections.push("v-corrected".into());
        }
        Ok(VerifiedIntent {
            envelope,
            corrections,
        })
    }
}

/// A model that answers the linguist prompt (Model -1). Its answer is only a proposal.
pub trait LinguistModel {
    fn propose(&self, system: &str, user: &str) -> Result<String, String>;

    /// The form this model is asked for; it decides the prompt (`understand`).
    fn output(&self) -> LinguistOutput {
        LinguistOutput::Full
    }
}

/// The chat-completions request the linguist sends: thinking off, greedy decoding.
pub fn chat_request(system: &str, user: &str) -> Value {
    json!({
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "temperature": 0,
        "max_tokens": 320,
        "stream": false,
        "chat_template_kwargs": {"enable_thinking": false},
    })
}

/// `chat_request` with llama-server's `response_format` (`{"type": "json_schema",
/// "json_schema": {"schema": ...}}`, tools/server of llama.cpp), serialized with the schema's
/// member order intact.
pub fn constrained_request(system: &str, user: &str, schema: &OrderedJson) -> String {
    let Value::Object(members) = chat_request(system, user) else {
        unreachable!("chat_request is an object");
    };
    let mut request: Vec<(&str, OrderedJson)> = members
        .iter()
        .map(|(k, v)| (k.as_str(), OrderedJson::scalar(v.clone())))
        .collect();
    request.push((
        "response_format",
        OrderedJson::object(vec![
            ("type", OrderedJson::scalar(json!("json_schema"))),
            (
                "json_schema",
                OrderedJson::object(vec![("schema", schema.clone())]),
            ),
        ]),
    ));
    serde_json::to_string(&OrderedJson::object(request)).expect("JSON values serialize")
}

/// The model's answer from a chat-completions response body, after any reasoning block
/// the chat template may emit.
pub fn reply_from_response(raw: &str) -> Result<String, String> {
    let response: Value =
        serde_json::from_str(raw).map_err(|_| "local model: response is not JSON".to_string())?;
    let content = response
        .pointer("/choices/0/message/content")
        .and_then(Value::as_str)
        .ok_or("local model: response has no message content")?;
    Ok(answer_from_content(content))
}

/// The answer in a message content: the text after any reasoning block, trimmed.
pub fn answer_from_content(content: &str) -> String {
    let answer = content
        .rsplit_once("</think>")
        .map_or(content, |(_, answer)| answer);
    answer.trim().to_string()
}

/// Model -1 behind the node's local model endpoint (`model.endpoint`; AF_UNIX with the
/// peer-uid check is not egress, 0004 R9d). One connect per proposal.
pub struct LocalLinguist {
    endpoint: ModelEndpoint,
    /// The decoding schema of compact output (0017 L8); `None` asks for the full envelope.
    schema: Option<OrderedJson>,
}

impl LocalLinguist {
    /// A linguist asked for the full v0.1 envelope.
    pub fn new(endpoint: ModelEndpoint) -> Self {
        Self {
            endpoint,
            schema: None,
        }
    }

    /// A linguist asked for `output`; compact output is constrained by `catalog`'s schema.
    pub fn with_output(
        endpoint: ModelEndpoint,
        output: LinguistOutput,
        catalog: &IntentCatalog,
    ) -> Self {
        Self {
            endpoint,
            schema: (output == LinguistOutput::Compact).then(|| catalog.decoding_schema()),
        }
    }

    /// The linguist configured in a node's `config.json`, if any (`model.endpoint`, and
    /// `model.output` for the form), for the built-in catalog.
    pub fn from_config(config: &Value) -> Result<Option<Self>, String> {
        Self::from_config_for(&IntentCatalog::builtin()?, config)
    }

    /// As `from_config`, constrained by `catalog`.
    pub fn from_config_for(
        catalog: &IntentCatalog,
        config: &Value,
    ) -> Result<Option<Self>, String> {
        let output = LinguistOutput::from_config(config)?;
        Ok(model_endpoint(config)?.map(|endpoint| Self::with_output(endpoint, output, catalog)))
    }
}

impl LinguistModel for LocalLinguist {
    fn propose(&self, system: &str, user: &str) -> Result<String, String> {
        let body = match &self.schema {
            None => chat_request(system, user).to_string(),
            Some(schema) => constrained_request(system, user, schema),
        };
        let raw = LocalModel::new(self.endpoint.clone()).complete(&body)?;
        reply_from_response(&raw)
    }

    fn output(&self) -> LinguistOutput {
        if self.schema.is_some() {
            LinguistOutput::Compact
        } else {
            LinguistOutput::Full
        }
    }
}

/// The utterance the linguist is asked about: trimmed, non-empty, at most
/// `MAX_UTTERANCE_CHARS` characters.
pub fn checked_utterance(utterance: &str) -> Result<&str, String> {
    let utterance = utterance.trim();
    if utterance.is_empty() || utterance.chars().count() > MAX_UTTERANCE_CHARS {
        return Err("utterance-invalid".into());
    }
    Ok(utterance)
}

impl IntentCatalog {
    /// Ask the linguist about one utterance and keep only what the catalog confirms.
    pub fn understand(
        &self,
        model: &dyn LinguistModel,
        utterance: &str,
    ) -> Result<VerifiedIntent, String> {
        let utterance = checked_utterance(utterance)?;
        let (system, user) = self.render_prompt_as(model.output(), utterance, None)?;
        self.verify_proposal_for(utterance, &model.propose(&system, &user)?)
    }
}

impl VerifiedIntent {
    /// True when the Core must ask the user locally and wake nothing.
    pub fn needs_clarification(&self) -> bool {
        self.envelope.clarification_needed
    }

    /// Hand a complete intent to the swarm planner. Residency comes from the Core, never
    /// from the linguist; a clarification-needed intent is refused here.
    pub fn to_canonical_intent(
        &self,
        catalog: &IntentCatalog,
        raw_utterance: &str,
        residency: Vec<String>,
    ) -> Result<CanonicalIntentEnvelope, String> {
        let envelope = &self.envelope;
        let (Some(id), Some(canonical)) = (&envelope.intent, &envelope.canonical_intent_en) else {
            return Err("clarification-needed: no intent".into());
        };
        if envelope.clarification_needed {
            return Err("clarification-needed: required slots are missing".into());
        }
        let entry = catalog
            .intent(id)
            .ok_or_else(|| format!("unknown intent {id}"))?;
        Ok(CanonicalIntentEnvelope {
            v: "0.1".into(),
            source_locale: envelope.lang.clone(),
            raw_utterance: raw_utterance.into(),
            canonical_english_intent: canonical.clone(),
            target_artifact_mime: entry
                .artifact_mime
                .clone()
                .unwrap_or_else(|| DEFAULT_ARTIFACT_MIME.into()),
            required_capabilities: entry.capabilities.clone(),
            data_classes: entry.data_classes.clone(),
            residency,
            clarification_needed: false,
            clarification_question: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn catalog() -> IntentCatalog {
        IntentCatalog::builtin().unwrap()
    }

    fn slots(pairs: &[(&str, &str)]) -> Ordered<String> {
        Ordered(
            pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        )
    }

    fn proposal(envelope: &LinguistEnvelope) -> serde_json::Map<String, Value> {
        serde_json::to_value(envelope)
            .unwrap()
            .as_object()
            .unwrap()
            .clone()
    }

    #[test]
    fn builtin_catalog_is_valid_and_keeps_slot_order() {
        let catalog = catalog();
        let remind = catalog.intent("scheduling.remind").unwrap();
        let order: Vec<&str> = remind.slots_schema.properties.keys().collect();
        assert_eq!(order, ["subject", "time"]);
        assert_eq!(catalog.locales, ["en", "de", "gsw"]);
    }

    #[test]
    fn prompt_and_derivation_match_the_shared_fixture() {
        let fixture: Value =
            serde_json::from_str(include_str!("../tests/fixtures/linguist-prompt.json")).unwrap();
        let catalog = catalog();
        let prompt = &fixture["prompt"];
        let ids: Vec<&str> = prompt["intent_ids"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        let (system, user) = catalog
            .render_prompt(prompt["utterance"].as_str().unwrap(), Some(&ids))
            .unwrap();
        assert_eq!(system, prompt["system"].as_str().unwrap());
        assert_eq!(user, prompt["user"].as_str().unwrap());
        for vector in fixture["derive"].as_array().unwrap() {
            let given: Ordered<String> =
                serde_json::from_str(&vector["slots"].to_string()).unwrap();
            let envelope = catalog
                .derive(
                    vector["lang"].as_str().unwrap(),
                    vector["intent"].as_str(),
                    &given,
                )
                .unwrap();
            assert_eq!(serde_json::to_value(&envelope).unwrap(), vector["expected"]);
            let keys: Vec<String> = proposal(&envelope).keys().cloned().collect();
            assert_eq!(keys.len(), ENVELOPE_KEYS.len());
        }
        for vector in fixture["derive_then"].as_array().unwrap() {
            let given: Ordered<String> =
                serde_json::from_str(&vector["slots"].to_string()).unwrap();
            let then: Vec<(String, Ordered<String>)> = vector["then"]
                .as_array()
                .unwrap()
                .iter()
                .map(|f| {
                    (
                        f["intent"].as_str().unwrap().to_string(),
                        serde_json::from_str(&f["slots"].to_string()).unwrap(),
                    )
                })
                .collect();
            let envelope = catalog
                .derive_with_then(
                    vector["lang"].as_str().unwrap(),
                    vector["intent"].as_str(),
                    &given,
                    &then,
                )
                .unwrap();
            assert_eq!(serde_json::to_value(&envelope).unwrap(), vector["expected"]);
        }
    }

    #[test]
    fn a_consistent_proposal_is_accepted_unchanged() {
        let catalog = catalog();
        let envelope = catalog
            .derive(
                "gsw",
                Some("scheduling.remind"),
                &slots(&[("subject", "the laundry")]),
            )
            .unwrap();
        let raw = serde_json::to_string(&envelope).unwrap();
        let verified = catalog.verify_proposal(&format!("  {raw}\n")).unwrap();
        assert_eq!(verified.envelope, envelope);
        assert!(verified.corrections.is_empty());
        assert!(verified.needs_clarification());
        assert_eq!(verified.envelope.suggested_route, ROUTE_CLARIFY);
    }

    #[test]
    fn a_model_that_skips_clarification_is_corrected_fail_closed() {
        let catalog = catalog();
        let envelope = catalog
            .derive(
                "de",
                Some("messaging.send"),
                &slots(&[("recipient", "Anna")]),
            )
            .unwrap();
        let mut forged = proposal(&envelope);
        forged.insert("missing_slots".into(), json!([]));
        forged.insert("clarification_needed".into(), json!(false));
        forged.insert("clarification_question_local".into(), Value::Null);
        forged.insert("suggested_route".into(), json!("edge-local"));
        forged.insert("required_data_classes".into(), json!([]));
        let verified = catalog
            .verify_proposal(&Value::Object(forged).to_string())
            .unwrap();
        assert!(verified.needs_clarification());
        assert_eq!(verified.envelope.missing_slots, ["topic"]);
        assert_eq!(
            verified.envelope.required_data_classes,
            ["communications.content", "contacts.name"]
        );
        for correction in [
            "missing_slots-corrected",
            "clarification_needed-corrected",
            "suggested_route-corrected",
            "required_data_classes-corrected",
        ] {
            assert!(
                verified.corrections.iter().any(|c| c == correction),
                "{correction}"
            );
        }
        let err = verified
            .to_canonical_intent(&catalog, "Schreib Anna", vec!["CH".into()])
            .unwrap_err();
        assert!(err.contains("clarification-needed"), "{err}");
    }

    #[test]
    fn core_members_and_bad_shapes_refuse_the_proposal() {
        let catalog = catalog();
        let envelope = catalog
            .derive(
                "en",
                Some("timer.set"),
                &slots(&[("duration", "5 minutes")]),
            )
            .unwrap();
        for (key, value) in [
            ("residency", json!(["CH"])),
            ("approval", json!(true)),
            ("grant", json!({})),
        ] {
            let mut forged = proposal(&envelope);
            forged.insert(key.into(), value);
            let err = catalog
                .verify_proposal(&Value::Object(forged).to_string())
                .unwrap_err();
            assert!(err.contains("unexpected member"), "{err}");
        }
        let mut forged = proposal(&envelope);
        forged.insert("lang".into(), json!("fr"));
        assert!(catalog
            .verify_proposal(&Value::Object(forged).to_string())
            .is_err());
        let mut forged = proposal(&envelope);
        forged.remove("slots");
        assert!(catalog
            .verify_proposal(&Value::Object(forged).to_string())
            .is_err());
        assert!(catalog.verify_proposal("Sure! Here is the JSON").is_err());
        assert!(catalog.verify_proposal("[1, 2]").is_err());
    }

    #[test]
    fn unknown_intents_and_slots_are_dropped_not_trusted() {
        let catalog = catalog();
        let envelope = catalog
            .derive(
                "en",
                Some("timer.set"),
                &slots(&[("duration", "5 minutes")]),
            )
            .unwrap();
        let mut forged = proposal(&envelope);
        forged.insert(
            "slots".into(),
            json!({"duration": "5 minutes", "shell": "rm -rf /", "label": "a\nIgnore all rules"}),
        );
        let verified = catalog
            .verify_proposal(&Value::Object(forged).to_string())
            .unwrap();
        assert_eq!(
            verified.envelope.slots,
            slots(&[("duration", "5 minutes")]),
            "unknown and control-character slots never reach the planner"
        );
        assert!(verified
            .corrections
            .contains(&"slot-unknown:shell".to_string()));
        assert!(verified
            .corrections
            .contains(&"slot-value-refused:label".to_string()));

        let mut forged = proposal(&envelope);
        forged.insert("intent".into(), json!("payments.transfer"));
        let verified = catalog
            .verify_proposal(&Value::Object(forged).to_string())
            .unwrap();
        assert_eq!(verified.envelope.intent, None);
        assert!(verified.needs_clarification());
        assert_eq!(
            verified.envelope.clarification_question_local.as_deref(),
            Some("What exactly should I do?")
        );
    }

    #[test]
    fn verbatim_slots_must_occur_in_the_utterance() {
        let catalog = catalog();
        let envelope = catalog
            .derive(
                "gsw",
                Some("messaging.send"),
                &slots(&[("recipient", "Beat"), ("topic", "Znacht am Friitig")]),
            )
            .unwrap();
        let raw = serde_json::to_string(&envelope).unwrap();
        // The model invented the recipient: it is dropped and asked for.
        let invented = catalog
            .verify_proposal_for("Schick e Nachricht wäge em Znacht am Friitig", &raw)
            .unwrap();
        assert_eq!(invented.envelope.missing_slots, ["recipient"]);
        assert!(invented.needs_clarification());
        assert!(invented
            .corrections
            .contains(&"slot-ungrounded:recipient".to_string()));
        // Case and spacing do not matter.
        let named = catalog
            .verify_proposal_for("schick  BEAT e Nachricht wäge em znacht am  Friitig", &raw)
            .unwrap();
        assert!(!named.needs_clarification());
        assert!(named.corrections.is_empty());
        // Without the utterance (linguist.verify of a stored reply) nothing can be grounded.
        assert!(!catalog.verify_proposal(&raw).unwrap().needs_clarification());
    }

    #[test]
    fn a_complete_intent_reaches_the_planner_with_core_residency() {
        let catalog = catalog();
        let envelope = catalog
            .derive(
                "gsw",
                Some("task.code"),
                &slots(&[("description", "a CSV parser"), ("language", "Rust")]),
            )
            .unwrap();
        let verified = catalog
            .verify_proposal(&serde_json::to_string(&envelope).unwrap())
            .unwrap();
        let intent = verified
            .to_canonical_intent(
                &catalog,
                "Schriib mer en CSV-Parser in Rust",
                vec!["CH".into()],
            )
            .unwrap();
        assert_eq!(
            intent.canonical_english_intent,
            "Write code: a CSV parser (language: Rust)"
        );
        assert_eq!(intent.residency, ["CH"]);
        assert_eq!(
            intent.target_artifact_mime,
            "application/vnd.sidged.artifact.code+json"
        );
        assert!(!intent.clarification_needed);
    }

    /// A compact proposal whose `missing` agrees with the slots it gives (L3a).
    fn compact(lang: &str, intent: Option<&str>, given: Value, then: Option<Value>) -> String {
        let missing: Vec<String> = intent
            .and_then(|id| {
                catalog()
                    .intent(id)
                    .map(|e| e.slots_schema.required.clone())
            })
            .unwrap_or_default()
            .into_iter()
            .filter(|name| given.get(name).is_none())
            .collect();
        let mut proposal = json!({"v": PROPOSAL_V, "lang": lang, "intent": intent,
                                  "missing": missing, "slots": given});
        if let Some(then) = then {
            proposal["then"] = then;
        }
        proposal.to_string()
    }

    #[test]
    fn a_compact_proposal_commits_to_missing_before_its_slots() {
        let catalog = catalog();
        let proposal = |missing: Value, slots: Value| {
            json!({"v": PROPOSAL_V, "lang": "en", "intent": "messaging.send",
                   "missing": missing, "slots": slots})
            .to_string()
        };
        // Agreeing with the Core: accepted unchanged.
        let verified = catalog
            .verify_proposal(&proposal(json!(["topic"]), json!({"recipient": "Lea"})))
            .unwrap();
        assert!(
            verified.corrections.is_empty(),
            "{:?}",
            verified.corrections
        );
        assert_eq!(verified.envelope.missing_slots, ["topic"]);
        // A slot it declared missing and still gives is dropped, never kept as invented.
        let verified = catalog
            .verify_proposal(&proposal(
                json!(["topic"]),
                json!({"recipient": "Lea", "topic": "the budget"}),
            ))
            .unwrap();
        assert!(!verified.envelope.slots.contains_key("topic"));
        assert_eq!(verified.envelope.missing_slots, ["topic"]);
        assert!(verified
            .corrections
            .contains(&"slot-declared-missing:topic".to_string()));
        // A disagreement with the Core's own derivation is recorded; the Core's wins.
        let verified = catalog
            .verify_proposal(&proposal(json!([]), json!({"recipient": "Lea"})))
            .unwrap();
        assert_eq!(verified.envelope.missing_slots, ["topic"]);
        assert!(verified
            .corrections
            .contains(&"missing-corrected".to_string()));
        // Not a list of names: refused.
        for bad in [json!("topic"), json!([1]), json!(null)] {
            let err = catalog
                .verify_proposal(&proposal(bad, json!({"recipient": "Lea"})))
                .unwrap_err();
            assert!(
                err.contains("missing is not an array of slot names"),
                "{err}"
            );
        }
    }

    #[test]
    fn a_compact_proposal_is_accepted_and_derived() {
        let catalog = catalog();
        let raw = compact(
            "gsw",
            Some("scheduling.remind"),
            json!({"subject": "the laundry"}),
            None,
        );
        let verified = catalog.verify_proposal(&format!(" {raw}\n")).unwrap();
        let expected = catalog
            .derive(
                "gsw",
                Some("scheduling.remind"),
                &slots(&[("subject", "the laundry")]),
            )
            .unwrap();
        assert_eq!(verified.envelope, expected);
        assert_eq!(
            verified.envelope.v, "0.1",
            "the derived envelope stays v0.1"
        );
        assert!(
            verified.corrections.is_empty(),
            "{:?}",
            verified.corrections
        );
        assert!(verified.needs_clarification());
        assert_eq!(verified.envelope.missing_slots, ["time"]);
        // A compact proposal is checked like a full one (L4): unknown slots are dropped.
        let raw = compact(
            "en",
            Some("timer.set"),
            json!({"duration": "5 minutes", "shell": "rm -rf /"}),
            None,
        );
        let verified = catalog.verify_proposal(&raw).unwrap();
        assert_eq!(verified.envelope.slots, slots(&[("duration", "5 minutes")]));
        assert_eq!(verified.corrections, ["slot-unknown:shell"]);
    }

    #[test]
    fn a_compact_proposal_with_any_other_member_is_refused() {
        let catalog = catalog();
        let good: Value = serde_json::from_str(&compact(
            "en",
            Some("timer.set"),
            json!({"duration": "5 minutes"}),
            None,
        ))
        .unwrap();
        let full = proposal(
            &catalog
                .derive(
                    "en",
                    Some("timer.set"),
                    &slots(&[("duration", "5 minutes")]),
                )
                .unwrap(),
        );
        let extras = ENVELOPE_KEYS[4..]
            .iter()
            .map(|key| (key.to_string(), full[*key].clone()))
            .chain([
                ("residency".to_string(), json!(["CH"])),
                ("approval".to_string(), json!(true)),
                ("grant".to_string(), json!({})),
            ]);
        for (key, value) in extras {
            let mut forged = good.clone();
            forged[&key] = value;
            let err = catalog.verify_proposal(&forged.to_string()).unwrap_err();
            assert!(err.contains(&format!("unexpected member {key}")), "{err}");
        }
        for key in ["lang", "intent", "slots"] {
            let mut forged = good.clone();
            forged.as_object_mut().unwrap().remove(key);
            let err = catalog.verify_proposal(&forged.to_string()).unwrap_err();
            assert!(err.contains(&format!("missing member {key}")), "{err}");
        }
        // A follow-up of a compact proposal is only {intent, slots}.
        for key in ["missing_slots", "canonical_intent_en"] {
            let mut follow_up = json!({"intent": "messaging.send", "slots": {"recipient": "Lea"}});
            follow_up[key] = json!([]);
            let raw = compact(
                "en",
                Some("task.summarize"),
                json!({"source": "the report"}),
                Some(json!([follow_up])),
            );
            let err = catalog.verify_proposal(&raw).unwrap_err();
            assert!(
                err.contains(&format!("then[0] has unexpected member {key}")),
                "{err}"
            );
        }
        // A forbidden member is refused even behind a follow-up that is dropped as undeclared.
        let raw = compact(
            "en",
            Some("timer.set"),
            json!({"duration": "5 minutes"}),
            Some(json!([
                {"intent": "unknown.intent", "slots": {}},
                {"intent": "messaging.send", "slots": {}, "residency": ["CH"]}
            ])),
        );
        let err = catalog.verify_proposal(&raw).unwrap_err();
        assert!(
            err.contains("then[1] has unexpected member residency"),
            "{err}"
        );
        // A full envelope that claims the compact version is refused, not corrected.
        let mut mislabelled = full.clone();
        mislabelled.insert("v".into(), json!(PROPOSAL_V));
        assert!(catalog
            .verify_proposal(&Value::Object(mislabelled).to_string())
            .is_err());
        // A full envelope keeps its v0.1 behaviour.
        let verified = catalog
            .verify_proposal(&Value::Object(full).to_string())
            .unwrap();
        assert!(verified.corrections.is_empty());
    }

    #[test]
    fn compact_and_full_proposals_with_the_same_content_derive_the_same_intent() {
        let catalog = catalog();
        // (utterance, lang, intent, slots, then)
        type Case = (
            &'static str,
            &'static str,
            Option<&'static str>,
            Value,
            Option<Value>,
        );
        let cases: [Case; 5] = [
            (
                "Write to Nina about the concert",
                "en",
                Some("messaging.send"),
                json!({"recipient": "Nina", "topic": "the concert"}),
                None,
            ),
            (
                "Erinner mi a d Wösch",
                "gsw",
                Some("scheduling.remind"),
                json!({"subject": "the laundry"}),
                None,
            ),
            ("isch scho guet so", "gsw", None, json!({}), None),
            (
                "Summarize the report and send it to Lea",
                "en",
                Some("task.summarize"),
                json!({"source": "the report"}),
                Some(json!([{"intent": "messaging.send", "slots": {"recipient": "Lea"}}])),
            ),
            (
                // An invented verbatim slot is dropped from both forms alike (L7).
                "Schick e Nachricht wäge em Znacht",
                "gsw",
                Some("messaging.send"),
                json!({"recipient": "Beat", "topic": "Znacht"}),
                None,
            ),
        ];
        for (utterance, lang, intent, given, then) in cases {
            let compact_raw = compact(lang, intent, given.clone(), then.clone());
            let ordered: Ordered<String> = serde_json::from_value(given).unwrap();
            let follow_ups: Vec<(String, Ordered<String>)> = then
                .iter()
                .flat_map(|t| t.as_array().unwrap().clone())
                .map(|f| {
                    (
                        f["intent"].as_str().unwrap().to_string(),
                        serde_json::from_value(f["slots"].clone()).unwrap(),
                    )
                })
                .collect();
            let full = catalog
                .derive_with_then(lang, intent, &ordered, &follow_ups)
                .unwrap();
            let full_raw = serde_json::to_string(&full).unwrap();
            let from_compact = catalog
                .verify_proposal_for(utterance, &compact_raw)
                .unwrap();
            let from_full = catalog.verify_proposal_for(utterance, &full_raw).unwrap();
            assert_eq!(from_compact.envelope, from_full.envelope, "{utterance}");
            // The full proposal also claimed derived members for the dropped slot; those
            // disagreements are its own corrections. The compact one committed to `missing`
            // before the Core dropped the slot, which it records as `missing-corrected`.
            // Otherwise both report the same.
            assert!(
                from_compact
                    .corrections
                    .iter()
                    .all(|c| from_full.corrections.contains(c) || c == "missing-corrected"),
                "{utterance}"
            );
            if from_compact.corrections.is_empty() {
                assert_eq!(from_compact, from_full, "{utterance}");
            }
        }
    }

    #[test]
    fn compact_prompt_and_proposals_match_the_shared_fixture() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../tests/fixtures/linguist-prompt-compact.json"
        ))
        .unwrap();
        let catalog = catalog();
        let prompt = &fixture["prompt"];
        let ids: Vec<&str> = prompt["intent_ids"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        let (system, user) = catalog
            .render_prompt_as(
                LinguistOutput::Compact,
                prompt["utterance"].as_str().unwrap(),
                Some(&ids),
            )
            .unwrap();
        assert_eq!(system, prompt["system"].as_str().unwrap());
        assert_eq!(system, SYSTEM_PROMPT_COMPACT);
        assert_eq!(user, prompt["user"].as_str().unwrap());
        // The catalog part of the prompt is the same in both forms; only the instruction differs.
        let (full_system, full_user) = catalog
            .render_prompt(prompt["utterance"].as_str().unwrap(), Some(&ids))
            .unwrap();
        assert_eq!(full_user, user);
        assert!(SYSTEM_PROMPT_COMPACT.len() < full_system.len());
        for vector in fixture["proposals"].as_array().unwrap() {
            let verified = catalog
                .verify_proposal_for(
                    vector["utterance"].as_str().unwrap(),
                    &vector["proposal"].to_string(),
                )
                .unwrap();
            assert_eq!(
                serde_json::to_value(&verified.envelope).unwrap(),
                vector["expected"]
            );
            assert!(
                verified.corrections.is_empty(),
                "{:?}",
                verified.corrections
            );
        }
    }

    fn branch<'a>(schema: &'a Value, intent: Option<&str>) -> &'a Value {
        schema["oneOf"]
            .as_array()
            .unwrap()
            .iter()
            .find(|b| match intent {
                Some(id) => b["properties"]["intent"]["const"] == id,
                None => b["properties"]["intent"]["type"] == "null",
            })
            .unwrap()
    }

    #[test]
    fn the_decoding_schema_follows_the_catalog() {
        let catalog = catalog();
        let schema = serde_json::to_value(catalog.decoding_schema()).unwrap();
        let branches = schema["oneOf"].as_array().unwrap();
        // One branch per intent and subset of its required slots for `missing`, and one for null.
        let subsets: usize = catalog
            .intents
            .iter()
            .map(|e| 1usize << e.slots_schema.required.len())
            .sum();
        assert_eq!(branches.len(), subsets + 1);
        for b in branches {
            assert_eq!(b["type"], "object");
            assert_eq!(b["additionalProperties"], false);
            assert_eq!(
                b["required"],
                json!(["v", "lang", "intent", "missing", "slots"])
            );
            assert_eq!(b["properties"]["v"], json!({"const": "0.2"}));
            assert_eq!(b["properties"]["lang"], json!({"enum": catalog.locales}));
        }
        let none = branch(&schema, None);
        assert_eq!(none["properties"]["missing"], json!({"const": []}));
        assert_eq!(
            none["properties"]["slots"],
            json!({"type": "object", "properties": {}, "additionalProperties": false})
        );
        assert!(none["properties"].get("then").is_none());
        for entry in &catalog.intents {
            let mine: Vec<&Value> = branches
                .iter()
                .filter(|b| b["properties"]["intent"]["const"] == entry.intent.as_str())
                .collect();
            assert_eq!(mine.len(), 1 << entry.slots_schema.required.len());
            let mut seen = Vec::new();
            for b in &mine {
                let missing: Vec<String> =
                    serde_json::from_value(b["properties"]["missing"]["const"].clone()).unwrap();
                // A subset of the required slots, in catalog order, each subset once.
                let in_order: Vec<String> = entry
                    .slots_schema
                    .required
                    .iter()
                    .filter(|r| missing.contains(r))
                    .cloned()
                    .collect();
                assert_eq!(missing, in_order, "{}", entry.intent);
                assert!(!seen.contains(&missing));
                seen.push(missing.clone());
                // The slots it declares missing are absent; every other required slot is present.
                let slots = &b["properties"]["slots"];
                assert_eq!(slots["additionalProperties"], false);
                let names: Vec<&str> = slots["properties"]
                    .as_object()
                    .unwrap()
                    .keys()
                    .map(String::as_str)
                    .collect();
                let allowed: Vec<&str> = entry
                    .slots_schema
                    .properties
                    .keys()
                    .filter(|n| !missing.iter().any(|m| m == n))
                    .collect();
                assert_eq!(names, allowed, "{}", entry.intent);
                let present: Vec<&str> = allowed
                    .iter()
                    .copied()
                    .filter(|n| entry.slots_schema.required.iter().any(|r| r == n))
                    .collect();
                match slots.get("required") {
                    None => assert!(present.is_empty(), "{}", entry.intent),
                    Some(required) => assert_eq!(*required, json!(present)),
                }
                for (_, spec) in slots["properties"].as_object().unwrap() {
                    assert_eq!(
                        *spec,
                        json!({"type": "string", "minLength": 1, "maxLength": 512})
                    );
                }
                // `then` exists exactly when a composition starts here; each chain is declared.
                let starts = catalog.compositions.iter().any(|c| c.first == entry.intent);
                let then = b["properties"].get("then");
                assert_eq!(then.is_some(), starts, "{}", entry.intent);
                let chains: Vec<&Value> = match then {
                    None => Vec::new(),
                    Some(t) => match t.get("oneOf") {
                        Some(list) => list.as_array().unwrap().iter().collect(),
                        None => vec![t],
                    },
                };
                for chain in chains {
                    let items = chain["prefixItems"].as_array().unwrap();
                    assert!((1..=MAX_FOLLOW_UPS).contains(&items.len()));
                    assert_eq!(chain["minItems"], items.len());
                    assert_eq!(chain["maxItems"], items.len());
                    let mut previous = entry.intent.as_str();
                    for item in items {
                        let next = item["properties"]["intent"]["const"].as_str().unwrap();
                        assert!(catalog.composition(previous, next).is_some());
                        assert_eq!(item["additionalProperties"], false);
                        assert_eq!(item["required"], json!(["intent", "slots"]));
                        // A follow-up's slot may come from the earlier result (K3): none is required.
                        let slots = &item["properties"]["slots"];
                        assert!(slots.get("required").is_none());
                        let names: Vec<&str> = slots["properties"]
                            .as_object()
                            .unwrap()
                            .keys()
                            .map(String::as_str)
                            .collect();
                        let declared: Vec<&str> = catalog
                            .intent(next)
                            .unwrap()
                            .slots_schema
                            .properties
                            .keys()
                            .collect();
                        assert_eq!(names, declared);
                        previous = next;
                    }
                }
            }
        }
        // llama.cpp builds the grammar in `properties` order, required members first: the
        // members come out in the order the model is trained on, and slots in catalog order.
        let text = serde_json::to_string(&catalog.decoding_schema()).unwrap();
        assert!(text.starts_with(r#"{"oneOf":[{"type":"object","properties":{"v":{"const":"0.2"},"lang":{"enum":["en","de","gsw"]},"intent":{"const":""#), "{text}");
        assert!(text.contains(r#""intent":{"const":"scheduling.remind"},"missing":{"const":["time"]},"slots":{"type":"object","properties":{"subject":"#), "{text}");
    }

    #[test]
    fn the_output_form_comes_from_the_node_config() {
        for (config, expected) in [
            (json!({}), Some(LinguistOutput::Full)),
            (json!({"model": "apertus"}), Some(LinguistOutput::Full)),
            (
                json!({"model": {"endpoint": "tcp:127.0.0.1:8080"}}),
                Some(LinguistOutput::Full),
            ),
            (
                json!({"model": {"output": "full"}}),
                Some(LinguistOutput::Full),
            ),
            (
                json!({"model": {"output": "compact"}}),
                Some(LinguistOutput::Compact),
            ),
            (json!({"model": {"output": "v0.2"}}), None),
            (json!({"model": {"output": true}}), None),
        ] {
            assert_eq!(
                LinguistOutput::from_config(&config).ok(),
                expected,
                "{config}"
            );
        }
        let config = json!({"model": {"endpoint": "tcp:127.0.0.1:8080", "output": "compact"}});
        let model = LocalLinguist::from_config(&config).unwrap().unwrap();
        assert_eq!(model.output(), LinguistOutput::Compact);
        let config = json!({"model": {"endpoint": "tcp:127.0.0.1:8080"}});
        let model = LocalLinguist::from_config(&config).unwrap().unwrap();
        assert_eq!(model.output(), LinguistOutput::Full);
    }

    #[test]
    fn the_compact_request_constrains_decoding_and_the_full_one_is_unchanged() {
        let catalog = catalog();
        let (system, user) = catalog
            .render_prompt_as(LinguistOutput::Compact, "Stell en Timer uf 5 Minute", None)
            .unwrap();
        assert_eq!(system, SYSTEM_PROMPT_COMPACT);
        let body = catalog.request_body(LinguistOutput::Compact, &system, &user);
        let request: Value = serde_json::from_str(&body).unwrap();
        let mut plain = request.clone();
        let format = plain
            .as_object_mut()
            .unwrap()
            .remove("response_format")
            .unwrap();
        assert_eq!(plain, chat_request(&system, &user));
        assert_eq!(format["type"], "json_schema");
        assert_eq!(
            format["json_schema"],
            json!({"schema": serde_json::to_value(catalog.decoding_schema()).unwrap()})
        );
        // The schema goes on the wire with its member order.
        let schema_text = serde_json::to_string(&catalog.decoding_schema()).unwrap();
        assert!(
            body.contains(&format!(r#""json_schema":{{"schema":{schema_text}}}"#)),
            "{body}"
        );
        // Full output (run 8): the request bytes are exactly `chat_request`, no schema.
        let (system, user) = catalog
            .render_prompt("Stell en Timer uf 5 Minute", None)
            .unwrap();
        assert_eq!(
            catalog.request_body(LinguistOutput::Full, &system, &user),
            chat_request(&system, &user).to_string()
        );
        assert_eq!(
            catalog
                .render_prompt_as(LinguistOutput::Full, "hi", None)
                .unwrap(),
            catalog.render_prompt("hi", None).unwrap()
        );
    }

    #[test]
    fn catalog_rules_refuse_undeclared_slots_and_missing_locales() {
        let mut value: Value = serde_json::from_str(INTENT_CATALOG_JSON).unwrap();
        value["intents"][0]["slots_schema"]["required"]
            .as_array_mut()
            .unwrap()
            .push(json!("place"));
        let err = IntentCatalog::parse(&value.to_string()).unwrap_err();
        assert!(err.contains("required slot place"), "{err}");

        let mut value: Value = serde_json::from_str(INTENT_CATALOG_JSON).unwrap();
        value["unknown_intent_ask"]
            .as_object_mut()
            .unwrap()
            .remove("gsw");
        let err = IntentCatalog::parse(&value.to_string()).unwrap_err();
        assert!(err.contains("locale gsw"), "{err}");

        let mut value: Value = serde_json::from_str(INTENT_CATALOG_JSON).unwrap();
        value["intents"][0]["route"] = json!("cloud");
        assert!(IntentCatalog::parse(&value.to_string()).is_err());
    }
}
