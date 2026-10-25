//! Where tagged data may be processed. Tags intersect. An unknown tag fails closed.

use std::collections::{BTreeSet, HashMap};

/// `None` is the intersection identity (`"any"`), including empty tags.
/// Egress permission is checked separately by `residency_destination`.
/// `Some` is the sorted region list, which may be empty.
pub fn allowed_regions(
    tags: &[String],
    owner: &HashMap<String, Vec<String>>,
) -> Result<Option<Vec<String>>, String> {
    let mut current: Option<BTreeSet<String>> = None;
    for tag in tags {
        if tag == "unrestricted" {
            continue;
        }
        let set = expand(tag, owner)?;
        current = Some(match current {
            None => set,
            Some(prior) => prior.intersection(&set).cloned().collect(),
        });
    }
    Ok(current.map(|regions| regions.into_iter().collect()))
}

pub fn provider_allows(
    tags: &[String],
    region: &str,
    owner: &HashMap<String, Vec<String>>,
) -> Result<bool, String> {
    match residency_destination(tags, region, owner) {
        Ok(()) => Ok(true),
        Err(reason) if reason == "residency-unsupported" => Ok(false),
        Err(reason) => Err(reason),
    }
}

fn expand(tag: &str, owner: &HashMap<String, Vec<String>>) -> Result<BTreeSet<String>, String> {
    match tag {
        "CH" => Ok(set(["CH"])),
        "EU" => Ok(set(["EU"])),
        "CH-EU" => Ok(set2(["CH", "EU"])),
        other if other.starts_with("x-") => {
            let Some(regions) = owner.get(other) else {
                return Err("residency-unknown-tag".into());
            };
            Ok(regions.iter().cloned().collect())
        }
        _ => Err("residency-unknown-tag".into()),
    }
}

fn set(regions: [&str; 1]) -> BTreeSet<String> {
    regions.into_iter().map(str::to_string).collect()
}

fn set2(regions: [&str; 2]) -> BTreeSet<String> {
    regions.into_iter().map(str::to_string).collect()
}

/// R8 egress permission, distinct from the region intersection identity.
pub fn residency_destination(
    tags: &[String],
    destination: &str,
    owner: &HashMap<String, Vec<String>>,
) -> Result<(), String> {
    if tags.len() > 1 && tags.iter().any(|tag| tag == "unrestricted") {
        return Err("malformed".into());
    }
    let allowed = allowed_regions(tags, owner)?;
    if tags.is_empty() || !matches!(destination, "CH" | "EU" | "GLOBAL") {
        return Err("residency-unsupported".into());
    }
    if allowed.is_none() || allowed.is_some_and(|regions| regions.iter().any(|r| r == destination))
    {
        Ok(())
    } else {
        Err("residency-unsupported".into())
    }
}
