/// VKR-L2 R9. A trailing `/*` is one prefix wildcard.
pub fn resource_covers(right: &str, resource: &str) -> bool {
    if right == resource {
        return true;
    }
    if !right.ends_with("/*") || !resource.starts_with(&right[..right.len() - 1]) {
        return false;
    }
    let rest = &resource[right.len() - 1..];
    if rest.is_empty() || rest.contains('%') {
        return false;
    }
    rest.split('/')
        .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
}

#[cfg(test)]
mod tests {
    use super::resource_covers;

    #[test]
    fn prefix_covers_a_child_segment() {
        assert!(resource_covers("urn:x:a/*", "urn:x:a/b"));
        assert!(resource_covers("urn:x:a/*", "urn:x:a/b/c"));
    }

    #[test]
    fn wildcard_does_not_escape() {
        assert!(!resource_covers("urn:x:a/*", "urn:x:a/"));
        assert!(!resource_covers("urn:x:a/*", "urn:x:a//b"));
        assert!(!resource_covers("urn:x:a/*", "urn:x:a/./b"));
        assert!(!resource_covers("urn:x:a/*", "urn:x:a/../b"));
        assert!(!resource_covers("urn:x:a/*", "urn:x:a/b/.."));
        assert!(!resource_covers("urn:x:a/*", "urn:x:a/%2e%2e/b"));
        assert!(!resource_covers("urn:x:a/*", "urn:x:a/b%2Fc"));
        assert!(!resource_covers("urn:x:a/*", "urn:x:ab"));
        assert!(!resource_covers("urn:x:a", "urn:x:a/b"));
    }
}
