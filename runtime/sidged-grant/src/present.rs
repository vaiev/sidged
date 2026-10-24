//! Accept a presented capability token before any step runs.
//!
//! Signature and holder binding are checked first. Expiry, attenuation, and
//! budget then use the same rules as `check_chain`. Cedar is a later step:
//! this function does not evaluate policy.
//!
//! `run_grant_vectors` is the `sidged vectors` check for the token-chain
//! vectors and the token-check vectors, including every expected refusal.

use std::fs;
use std::path::Path;

use serde_json::Value;

use crate::chain::verify_token_chain;
use crate::token::{
    check_chain, Budget, Confirmation, Constraints, GrantError, Money, Right, Token, TokenLink,
};

/// Schema, lifetime, and attenuation only. No clock and no signature.
/// This is the `token-check` operation. Presentation uses `accept_presented`.
pub fn structural_token(document: &Value) -> Result<(), GrantError> {
    let token = token_from(document)?;
    check_chain(&token, None)
}

pub fn run_grant_vectors(root: &Path) -> Result<String, String> {
    let mut problems = Vec::new();
    let mut chain = 0usize;
    let mut checks = 0usize;
    let mut refused = 0usize;
    walk_vectors(root, &mut problems, &mut chain, &mut checks, &mut refused)?;
    if !problems.is_empty() {
        return Err(problems.join("\n"));
    }
    Ok(format!(
        "token-chain {chain}\ntoken-check {checks}\nrefused {refused}"
    ))
}

fn walk_vectors(
    dir: &Path,
    problems: &mut Vec<String>,
    chain: &mut usize,
    checks: &mut usize,
    refused: &mut usize,
) -> Result<(), String> {
    let entries = fs::read_dir(dir).map_err(|err| err.to_string())?;
    for entry in entries {
        let path = entry.map_err(|err| err.to_string())?.path();
        if path.is_dir() {
            walk_vectors(&path, problems, chain, checks, refused)?;
            continue;
        }
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let text = fs::read_to_string(&path).map_err(|err| err.to_string())?;
        let Ok(file) = serde_json::from_str::<Value>(&text) else {
            continue;
        };
        let Some(vectors) = file.get("vectors").and_then(Value::as_array) else {
            continue;
        };
        for vector in vectors {
            let id = vector["id"].as_str().unwrap_or("?");
            let expected = vector["expected"]["result"].as_str().unwrap_or("");
            match vector["operation"].as_str().unwrap_or("") {
                "token-chain" => {
                    *chain += 1;
                    if expected == "refuse" {
                        *refused += 1;
                    }
                    let got = if verify_token_chain(&vector["input"]["token"]).is_ok() {
                        "accept"
                    } else {
                        "refuse"
                    };
                    if got != expected {
                        problems.push(format!("{id}: token-chain got {got}"));
                    }
                }
                "token-check" => {
                    *checks += 1;
                    if expected == "refuse" {
                        *refused += 1;
                    }
                    let got = if structural_token(&vector["input"]["token"]).is_ok() {
                        "accept"
                    } else {
                        "refuse"
                    };
                    if got != expected {
                        problems.push(format!("{id}: token-check got {got}"));
                    }
                }
                _ => {}
            }
        }
    }
    Ok(())
}

pub fn accept_presented(
    document: &Value,
    now: &str,
    trusted_roots: &[&str],
) -> Result<Token, GrantError> {
    verify_token_chain(document).map_err(|message| classify(&message))?;
    let token = token_from(document)?;
    check_chain(&token, Some(now))?;
    let root = token
        .chain
        .first()
        .map(|link| link.iss.as_str())
        .unwrap_or(token.link.iss.as_str());
    if trusted_roots.is_empty() || !trusted_roots.contains(&root) {
        return Err(GrantError::UntrustedIssuer);
    }
    Ok(token)
}

fn classify(message: &str) -> GrantError {
    if message.contains("holder") || message.contains("thumbprint") || message.contains("cnf.") {
        GrantError::Holder
    } else if message.contains("signature") || message.contains("sig") || message.contains("base64")
    {
        GrantError::Signature
    } else {
        GrantError::Malformed
    }
}

fn token_from(value: &Value) -> Result<Token, GrantError> {
    let chain = value
        .get("chain")
        .and_then(Value::as_array)
        .ok_or(GrantError::Malformed)?;
    let chain = chain.iter().map(link_from).collect::<Result<Vec<_>, _>>()?;
    Ok(Token {
        link: link_from(value)?,
        chain,
    })
}

fn link_from(value: &Value) -> Result<TokenLink, GrantError> {
    if value.get("v").and_then(Value::as_str) != Some("0.1") {
        return Err(GrantError::Malformed);
    }
    let rights = value
        .get("rights")
        .and_then(Value::as_array)
        .ok_or(GrantError::Malformed)?;
    if rights.is_empty() {
        return Err(GrantError::Malformed);
    }
    Ok(TokenLink {
        iss: required_string(value, "iss")?,
        sub: required_string(value, "sub")?,
        aud: required_string(value, "aud")?,
        iat: required_string(value, "iat")?,
        nbf: optional_string(value.get("nbf"))?,
        exp: required_string(value, "exp")?,
        cnf: Confirmation {
            jkt: optional_string(value.get("cnf").and_then(|cnf| cnf.get("jkt")))?,
            kid: optional_string(value.get("cnf").and_then(|cnf| cnf.get("kid")))?,
        },
        rights: rights
            .iter()
            .map(right_from)
            .collect::<Result<Vec<_>, _>>()?,
        budget: budget_from(value.get("budget").unwrap_or(&Value::Null))?,
    })
}

pub(crate) fn right_from(value: &Value) -> Result<Right, GrantError> {
    let constraints = value.get("constraints").unwrap_or(&Value::Null);
    Ok(Right {
        action: required_string(value, "action")?,
        resource: required_string(value, "resource")?,
        constraints: constraints_from(constraints)?,
    })
}

fn constraints_from(value: &Value) -> Result<Constraints, GrantError> {
    if value.is_null() {
        return Ok(Constraints::default());
    }
    let object = value.as_object().ok_or(GrantError::Malformed)?;
    Ok(Constraints {
        max_uses: optional_u64(object.get("max_uses"))?,
        max_amount: optional_money(object.get("max_amount"))?,
        data_classes: match object.get("data_classes") {
            None => None,
            Some(classes) => Some(string_list(classes)?),
        },
    })
}

pub(crate) fn budget_from(value: &Value) -> Result<Budget, GrantError> {
    if value.is_null() {
        return Ok(Budget::default());
    }
    let object = value.as_object().ok_or(GrantError::Malformed)?;
    Ok(Budget {
        messages: optional_u64(object.get("messages"))?,
        compute_units: optional_u64(object.get("compute_units"))?,
        money: optional_money(object.get("money"))?,
    })
}

fn optional_money(value: Option<&Value>) -> Result<Option<Money>, GrantError> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    Ok(Some(Money {
        amount: required_string(value, "amount")?,
        currency: required_string(value, "currency")?,
    }))
}

fn optional_u64(value: Option<&Value>) -> Result<Option<u64>, GrantError> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value.as_u64().map(Some).ok_or(GrantError::Malformed),
    }
}

fn optional_string(value: Option<&Value>) -> Result<Option<String>, GrantError> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) => Ok(Some(text.clone())),
        Some(_) => Err(GrantError::Malformed),
    }
}

fn required_string(value: &Value, key: &str) -> Result<String, GrantError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or(GrantError::Malformed)
}

fn string_list(value: &Value) -> Result<Vec<String>, GrantError> {
    value
        .as_array()
        .ok_or(GrantError::Malformed)?
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_string)
                .ok_or(GrantError::Malformed)
        })
        .collect()
}
