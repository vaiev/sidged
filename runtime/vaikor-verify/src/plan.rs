use std::collections::{HashMap, HashSet};

use cel::Program;

const MAX_STEPS: usize = 32;
const MAX_BOUND: u32 = 32;

/// A step argument (0003 §1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Arg {
    /// A literal: a string, number, boolean or null.
    Lit(serde_json::Value),
    /// The output of an earlier step, or its member `field` (R4a), with that step's labels.
    Ref { step: String, field: Option<String> },
    /// The current element of a `map`.
    Item,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    Call {
        id: String,
        capability: String,
        approval: bool,
        args: Vec<(String, Arg)>,
    },
    Expr {
        id: String,
        expr: String,
    },
    Map {
        id: String,
        over: String,
        bound: u32,
        capability: String,
        approval: bool,
        args: Vec<(String, Arg)>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub budget: Option<(String, String)>,
    pub steps: Vec<Step>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cap {
    pub effects: Vec<String>,
    pub data_classes: Vec<String>,
    pub consequential: bool,
    pub cost: Option<(String, String)>,
    /// The property names the descriptor's `output_schema` declares (R4a).
    pub outputs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Summary {
    pub capabilities: Vec<String>,
    pub approvals: Vec<String>,
    pub egress: Vec<String>,
}

pub trait FlowPolicy {
    fn allow_egress(&self, class: &str, capability: &str) -> bool;
}

/// Structural stage that defers every egress decision to the Cedar flow stage
/// (`flow::check_plan_flows`), which refuses `secrets.*` unconditionally and sensitive
/// classes without an owner permit. Use only together with that stage.
#[derive(Debug, Default, Clone, Copy)]
pub struct DeferToCedar;

impl FlowPolicy for DeferToCedar {
    fn allow_egress(&self, _class: &str, _capability: &str) -> bool {
        true
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct DenySensitive;

impl FlowPolicy for DenySensitive {
    fn allow_egress(&self, _class: &str, _capability: &str) -> bool {
        false
    }
}

#[derive(Debug, Clone)]
pub struct AllowList {
    pub pairs: HashSet<(String, String)>,
}

impl FlowPolicy for AllowList {
    fn allow_egress(&self, class: &str, capability: &str) -> bool {
        self.pairs
            .contains(&(class.to_string(), capability.to_string()))
    }
}

pub fn verify(
    plan: &Plan,
    catalog: &HashMap<String, Cap>,
    policy: &impl FlowPolicy,
) -> Result<Summary, Vec<String>> {
    let mut problems = Vec::new();
    if plan.steps.is_empty() || plan.steps.len() > MAX_STEPS {
        problems.push("a plan has between 1 and 32 steps".to_string());
    }
    let mut seen = HashSet::new();
    let mut labels: HashMap<String, HashSet<String>> = HashMap::new();
    // R4a: the output members each earlier step declares; an `expr` or a `map` declares none.
    let mut outputs: HashMap<String, &[String]> = HashMap::new();
    let mut capabilities = Vec::new();
    let mut approvals = Vec::new();
    let mut egress = Vec::new();
    let mut total = Decimal::zero();
    let mut currency: Option<String> = None;
    let mut metered = false;

    for step in &plan.steps {
        let id = step.id();
        if !seen.insert(id.to_string()) {
            problems.push(format!("{id}: duplicated step id"));
            continue;
        }
        match step {
            Step::Expr { expr, .. } => match expr_refs(expr) {
                Ok(names) => {
                    let mut acc = HashSet::new();
                    for name in names {
                        match labels.get(&name) {
                            Some(prior) => acc.extend(prior.iter().cloned()),
                            None => problems.push(format!("{id}: {name} is not an earlier step")),
                        }
                    }
                    labels.insert(id.to_string(), acc);
                }
                Err(message) => {
                    problems.push(format!("{id}: {message}"));
                    labels.insert(id.to_string(), HashSet::new());
                }
            },
            Step::Call {
                capability,
                approval,
                args,
                ..
            } => {
                let Some(cap) = catalog.get(capability) else {
                    problems.push(format!("{id}: unknown capability {capability}"));
                    labels.insert(id.to_string(), HashSet::new());
                    continue;
                };
                let arg_labels = arg_labels(args, &labels, &outputs, None, &mut problems, id);
                outputs.insert(id.to_string(), cap.outputs.as_slice());
                account(
                    id,
                    capability,
                    cap,
                    &arg_labels,
                    *approval,
                    1,
                    policy,
                    &mut labels,
                    &mut capabilities,
                    &mut approvals,
                    &mut egress,
                    &mut problems,
                );
                add_cost(
                    cap,
                    1,
                    &mut total,
                    &mut currency,
                    &mut metered,
                    &mut problems,
                    id,
                );
            }
            Step::Map {
                over,
                bound,
                capability,
                approval,
                args,
                ..
            } => {
                if *bound == 0 || *bound > MAX_BOUND {
                    problems.push(format!("{id}: map bound must be an integer from 1 to 32"));
                }
                let item = match labels.get(over) {
                    Some(prior) => prior.clone(),
                    None => {
                        problems.push(format!("{id}: map over is not an earlier step"));
                        HashSet::new()
                    }
                };
                let Some(cap) = catalog.get(capability) else {
                    problems.push(format!("{id}: unknown capability {capability}"));
                    labels.insert(id.to_string(), HashSet::new());
                    continue;
                };
                // 0003 R10: how often the capability runs depends on the list, so its labels
                // reach the step even when no argument is the item (an implicit flow).
                let mut arg_labels =
                    arg_labels(args, &labels, &outputs, Some(&item), &mut problems, id);
                arg_labels.extend(item);
                account(
                    id,
                    capability,
                    cap,
                    &arg_labels,
                    *approval,
                    *bound,
                    policy,
                    &mut labels,
                    &mut capabilities,
                    &mut approvals,
                    &mut egress,
                    &mut problems,
                );
                add_cost(
                    cap,
                    *bound,
                    &mut total,
                    &mut currency,
                    &mut metered,
                    &mut problems,
                    id,
                );
            }
        }
    }
    if metered {
        match &plan.budget {
            None => problems.push("metered plan requires budget.max".to_string()),
            Some((amount, budget_currency)) => {
                if !is_money(amount, budget_currency) {
                    problems.push("budget.max is not a decimal amount and currency".to_string());
                } else if currency.as_deref() != Some(budget_currency) {
                    problems.push("budget currency does not match capability costs".to_string());
                } else if !decimal_le(&total.render(), amount) {
                    problems.push(format!(
                        "maximum cost {} exceeds budget {amount}",
                        total.render()
                    ));
                }
            }
        }
    }
    if problems.is_empty() {
        Ok(Summary {
            capabilities,
            approvals,
            egress,
        })
    } else {
        Err(problems)
    }
}

#[allow(clippy::too_many_arguments)] // existing verifier helper; refactor out of scope for A1
fn account(
    id: &str,
    capability: &str,
    cap: &Cap,
    arg_labels: &HashSet<String>,
    approval: bool,
    _bound: u32,
    policy: &impl FlowPolicy,
    labels: &mut HashMap<String, HashSet<String>>,
    capabilities: &mut Vec<String>,
    approvals: &mut Vec<String>,
    egress: &mut Vec<String>,
    problems: &mut Vec<String>,
) {
    let mut out = arg_labels.clone();
    out.extend(cap.data_classes.iter().cloned());
    if cap.effects.iter().any(|effect| effect == "egress") {
        egress.push(capability.to_string());
        for class in arg_labels.iter().chain(cap.data_classes.iter()) {
            if sensitive(class) && !policy.allow_egress(class, capability) {
                problems.push(format!(
                    "{id}: {class} reaches egress capability {capability}"
                ));
            }
        }
    }
    if cap.consequential && !approval {
        problems.push(format!("{id}: consequential capability requires approval"));
    }
    if approval {
        approvals.push(id.to_string());
    }
    capabilities.push(capability.to_string());
    labels.insert(id.to_string(), out);
}

fn arg_labels(
    args: &[(String, Arg)],
    labels: &HashMap<String, HashSet<String>>,
    outputs: &HashMap<String, &[String]>,
    item: Option<&HashSet<String>>,
    problems: &mut Vec<String>,
    id: &str,
) -> HashSet<String> {
    let mut acc = HashSet::new();
    for (_, arg) in args {
        match arg {
            Arg::Lit(_) => {}
            Arg::Ref { step, field } => match labels.get(step) {
                Some(prior) => {
                    // R4a: a member keeps the producer's labels and must be declared.
                    acc.extend(prior.iter().cloned());
                    if let Some(field) = field {
                        let declared = outputs.get(step).copied().unwrap_or_default();
                        if !declared.iter().any(|name| name == field) {
                            problems.push(format!(
                                "{id}: ref {step} has no declared output member {field}"
                            ));
                        }
                    }
                }
                None => problems.push(format!("{id}: ref {step} is not an earlier step")),
            },
            Arg::Item => match item {
                Some(prior) => acc.extend(prior.iter().cloned()),
                None => problems.push(format!("{id}: item is only valid inside a map")),
            },
        }
    }
    acc
}

fn add_cost(
    cap: &Cap,
    bound: u32,
    total: &mut Decimal,
    currency: &mut Option<String>,
    metered: &mut bool,
    problems: &mut Vec<String>,
    id: &str,
) {
    let Some((amount, step_currency)) = &cap.cost else {
        return;
    };
    *metered = true;
    if !is_money(amount, step_currency) {
        problems.push(format!(
            "{id}: cost max is not a decimal amount and currency"
        ));
        return;
    }
    match currency {
        None => *currency = Some(step_currency.clone()),
        Some(current) if current != step_currency => {
            problems.push(format!(
                "{id}: cost currency {step_currency} does not match {current}"
            ));
            return;
        }
        _ => {}
    }
    let mut value = Decimal::parse(amount);
    value.mul(bound);
    total.add(&value);
}

/// Bounds on an expression before the CEL parser sees it (0003 R8a). The parser recurses per
/// bracket level and overflows the stack (an abort, not a panic) from about 8 levels in a
/// debug build on a 1 MiB stack, so plan v0 allows 4 levels and the schema's 1024 characters.
const MAX_EXPR_CHARS: usize = 1024;
const MAX_EXPR_NESTING: usize = 4;

/// Compile a plan expression within the R8a bounds. Brackets are counted everywhere, string
/// literals included, so the bound never depends on how a literal is lexed.
pub(crate) fn compile_expr(expr: &str) -> Result<Program, String> {
    if expr.chars().count() > MAX_EXPR_CHARS {
        return Err(format!(
            "expression is longer than {MAX_EXPR_CHARS} characters"
        ));
    }
    let mut depth = 0usize;
    for c in expr.chars() {
        match c {
            '(' | '[' | '{' => {
                depth += 1;
                if depth > MAX_EXPR_NESTING {
                    return Err(format!(
                        "expression nests brackets deeper than {MAX_EXPR_NESTING}"
                    ));
                }
            }
            ')' | ']' | '}' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    Program::compile(expr).map_err(|err| err.to_string())
}

fn expr_refs(expr: &str) -> Result<Vec<String>, String> {
    let program = compile_expr(expr)?;
    let references = program.references();
    for name in ["filter", "map", "all", "exists", "exists_one"] {
        if references.has_function(name) {
            return Err(format!("comprehension macro {name} is not in plan v0"));
        }
    }
    Ok(references
        .variables()
        .into_iter()
        .map(str::to_string)
        .collect())
}

/// The money profile of `common.schema.json`: `^[0-9]+(\.[0-9]+)?$` and `^[A-Z]{3}$`. Amounts
/// are checked before any arithmetic, which assumes ASCII digits.
fn is_money(amount: &str, currency: &str) -> bool {
    let digits = |part: &str| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit());
    let amount_ok = match amount.split_once('.') {
        Some((integer, fraction)) => digits(integer) && digits(fraction),
        None => digits(amount),
    };
    amount_ok && currency.len() == 3 && currency.bytes().all(|b| b.is_ascii_uppercase())
}

fn sensitive(name: &str) -> bool {
    name == "health.records"
        || name.starts_with("health.records.")
        || name == "secrets"
        || name.starts_with("secrets.")
}

#[derive(Clone, Debug)]
struct Decimal {
    // TODO: negative amounts are never represented (always false);
    // tracked as a known gap rather than silently suppressed. Kept to avoid touching verifier logic.
    #[allow(dead_code)]
    negative: bool,
    digits: String,
    scale: usize,
}

impl Decimal {
    fn zero() -> Self {
        Self {
            negative: false,
            digits: "0".to_string(),
            scale: 0,
        }
    }

    fn parse(value: &str) -> Self {
        let (integer, fraction) = value.split_once('.').unwrap_or((value, ""));
        let mut digits = format!("{integer}{fraction}")
            .trim_start_matches('0')
            .to_string();
        if digits.is_empty() {
            digits = "0".to_string();
        }
        Self {
            negative: false,
            digits,
            scale: fraction.len(),
        }
    }

    fn mul(&mut self, factor: u32) {
        if factor == 0 || self.digits == "0" {
            *self = Self::zero();
            return;
        }
        let mut carry = 0u64;
        let mut out = Vec::new();
        for byte in self.digits.bytes().rev() {
            let value = u64::from(byte - b'0') * u64::from(factor) + carry;
            out.push(char::from(b'0' + (value % 10) as u8));
            carry = value / 10;
        }
        while carry > 0 {
            out.push(char::from(b'0' + (carry % 10) as u8));
            carry /= 10;
        }
        self.digits = out.into_iter().rev().collect();
    }

    fn add(&mut self, other: &Decimal) {
        let scale = self.scale.max(other.scale);
        let left = self.scaled(scale);
        let right = other.scaled(scale);
        let (mut left, mut right) = (left.bytes().rev(), right.bytes().rev());
        let mut carry = 0u8;
        let mut out = Vec::new();
        loop {
            let (l, r) = (left.next(), right.next());
            if l.is_none() && r.is_none() {
                break;
            }
            let digit = |b: Option<u8>| b.map_or(0, |b| b - b'0');
            let sum = digit(l) + digit(r) + carry;
            out.push(char::from(b'0' + sum % 10));
            carry = sum / 10;
        }
        if carry > 0 {
            out.push(char::from(b'0' + carry));
        }
        self.digits = out.into_iter().rev().collect();
        self.scale = scale;
    }

    fn scaled(&self, scale: usize) -> String {
        let mut digits = self.digits.clone();
        digits.extend(std::iter::repeat_n('0', scale - self.scale));
        digits
    }

    fn render(&self) -> String {
        if self.scale == 0 {
            return self.digits.clone();
        }
        let digits = if self.digits.len() <= self.scale {
            format!(
                "{}{}",
                "0".repeat(self.scale - self.digits.len() + 1),
                self.digits
            )
        } else {
            self.digits.clone()
        };
        let split = digits.len() - self.scale;
        format!("{}.{}", &digits[..split], &digits[split..])
    }
}

fn decimal_le(left: &str, right: &str) -> bool {
    cmp_decimal(left, right) != std::cmp::Ordering::Greater
}

fn cmp_decimal(left: &str, right: &str) -> std::cmp::Ordering {
    let (left_int, left_frac) = split_decimal(left);
    let (right_int, right_frac) = split_decimal(right);
    match cmp_int(left_int, right_int) {
        std::cmp::Ordering::Equal => cmp_frac(left_frac, right_frac),
        other => other,
    }
}

fn split_decimal(value: &str) -> (&str, &str) {
    value.split_once('.').unwrap_or((value, ""))
}

fn cmp_int(left: &str, right: &str) -> std::cmp::Ordering {
    let left = left.trim_start_matches('0');
    let right = right.trim_start_matches('0');
    let left = if left.is_empty() { "0" } else { left };
    let right = if right.is_empty() { "0" } else { right };
    left.len().cmp(&right.len()).then_with(|| left.cmp(right))
}

fn cmp_frac(left: &str, right: &str) -> std::cmp::Ordering {
    let width = left.len().max(right.len());
    for index in 0..width {
        let left_digit = left.as_bytes().get(index).copied().unwrap_or(b'0');
        let right_digit = right.as_bytes().get(index).copied().unwrap_or(b'0');
        if left_digit != right_digit {
            return left_digit.cmp(&right_digit);
        }
    }
    std::cmp::Ordering::Equal
}

impl Step {
    fn id(&self) -> &str {
        match self {
            Step::Call { id, .. } | Step::Expr { id, .. } | Step::Map { id, .. } => id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn send() -> Cap {
        Cap {
            effects: vec!["egress".into()],
            data_classes: vec!["communications.content".into()],
            consequential: true,
            cost: None,
            outputs: Vec::new(),
        }
    }

    #[test]
    fn health_records_do_not_reach_egress() {
        let mut catalog = HashMap::new();
        catalog.insert(
            "tag:vaikor.com,2026:capability:records.read".into(),
            Cap {
                effects: vec!["read".into()],
                data_classes: vec!["health.records".into()],
                consequential: false,
                cost: None,
                outputs: Vec::new(),
            },
        );
        catalog.insert("tag:vaikor.com,2026:capability:message.send".into(), send());
        let plan = Plan {
            budget: None,
            steps: vec![
                Step::Call {
                    id: "notes".into(),
                    capability: "tag:vaikor.com,2026:capability:records.read".into(),
                    approval: false,
                    args: vec![],
                },
                Step::Call {
                    id: "send".into(),
                    capability: "tag:vaikor.com,2026:capability:message.send".into(),
                    approval: true,
                    args: vec![(
                        "body".into(),
                        Arg::Ref {
                            step: "notes".into(),
                            field: None,
                        },
                    )],
                },
            ],
        };
        assert!(verify(&plan, &catalog, &DenySensitive).is_err());
    }

    #[test]
    fn a_cel_macro_is_rejected() {
        let plan = Plan {
            budget: None,
            steps: vec![
                Step::Expr {
                    id: "free".into(),
                    expr: "true".into(),
                },
                Step::Expr {
                    id: "bad".into(),
                    expr: "free.filter(x, x > 0)".into(),
                },
            ],
        };
        assert!(verify(&plan, &HashMap::new(), &DenySensitive).is_err());
    }

    #[test]
    fn expressions_are_bounded_before_the_parser_sees_them() {
        let expr = |text: String| Plan {
            budget: None,
            steps: vec![Step::Expr {
                id: "e".into(),
                expr: text,
            }],
        };
        let catalog = HashMap::new();
        assert!(verify(&expr("[[[[1]]]]".into()), &catalog, &DenySensitive).is_ok());
        for deep in ["(((((1)))))", "[[[[[]]]]]", "f(g(h(i(j(1)))))", "'(((((('"] {
            assert!(
                verify(&expr(deep.into()), &catalog, &DenySensitive).is_err(),
                "{deep}"
            );
        }
        // Far past the bound: refused without recursing (this overflowed the stack before R8a).
        let abyss = format!("{}1{}", "(".repeat(5000), ")".repeat(5000));
        assert!(verify(&expr(abyss), &catalog, &DenySensitive).is_err());
        let long = format!("1{}", "+1".repeat(512));
        assert!(verify(&expr(long), &catalog, &DenySensitive).is_err());
        for broken in ["1 +", "é", "🙂", ")", "((", ""] {
            assert!(
                verify(&expr(broken.into()), &catalog, &DenySensitive).is_err(),
                "{broken}"
            );
        }
    }

    fn metered(amount: &str, bound: u32, budget: &str) -> Result<Summary, Vec<String>> {
        let mut catalog = HashMap::new();
        catalog.insert(
            "tag:vaikor.com,2026:capability:api.call".into(),
            Cap {
                effects: vec!["read".into()],
                data_classes: vec!["public".into()],
                consequential: false,
                cost: Some((amount.into(), "CHF".into())),
                outputs: Vec::new(),
            },
        );
        let plan = Plan {
            budget: Some((budget.into(), "CHF".into())),
            steps: vec![
                Step::Expr {
                    id: "items".into(),
                    expr: "[1, 2]".into(),
                },
                Step::Map {
                    id: "each".into(),
                    over: "items".into(),
                    bound,
                    capability: "tag:vaikor.com,2026:capability:api.call".into(),
                    approval: false,
                    args: vec![("q".into(), Arg::Item)],
                },
            ],
        };
        verify(&plan, &catalog, &DenySensitive)
    }

    #[test]
    fn metered_costs_add_up_against_the_budget() {
        assert!(metered("0.25", 4, "1").is_ok());
        assert!(metered("0.25", 4, "0.99").is_err());
        assert!(metered("10", 32, "320.00").is_ok());
    }

    #[test]
    fn amounts_outside_the_money_pattern_are_refused_not_computed() {
        for amount in ["1x", "", ".5", "5.", "-1", "1e3", " 1", "1,5", "٣"] {
            let costed = metered(amount, 2, "10");
            assert!(costed.is_err(), "cost {amount:?} accepted");
            let budgeted = metered("1", 2, amount);
            assert!(budgeted.is_err(), "budget {amount:?} accepted");
        }
    }

    #[test]
    fn an_out_of_range_bound_never_overflows_the_cost() {
        assert!(metered("9", u32::MAX, "1000000000000000").is_err());
    }

    #[test]
    fn long_amounts_are_added_in_linear_time() {
        let long = "9".repeat(200_000);
        let started = std::time::Instant::now();
        assert!(metered(&long, 32, &long).is_err());
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }
}
