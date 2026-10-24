/// Format Unix seconds as `YYYY-MM-DDTHH:MM:SSZ`.
pub fn format_rfc3339_z(seconds: i64) -> String {
    let days = seconds.div_euclid(86_400);
    let tod = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = tod / 3_600;
    let minute = (tod % 3_600) / 60;
    let second = tod % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Add seconds to a `YYYY-MM-DDTHH:MM:SSZ` timestamp.
pub fn add_rfc3339_z(stamp: &str, seconds: i64) -> Option<String> {
    Some(format_rfc3339_z(parse_rfc3339_z(stamp)? + seconds))
}

/// Parse an RFC 3339 timestamp to Unix seconds.
///
/// `Z` and a numeric offset (`+HH:MM` or `-HH:MM`) name the same instant.
/// Fractional seconds are refused.
pub fn parse_rfc3339_z(value: &str) -> Option<i64> {
    let bytes = value.as_bytes();
    if bytes.len() < 20 || bytes[10] != b'T' {
        return None;
    }
    let instant = civil_seconds(&bytes[..19])?;
    if bytes.len() == 20 && bytes[19] == b'Z' {
        return Some(instant);
    }
    if bytes.len() == 25 && (bytes[19] == b'+' || bytes[19] == b'-') && bytes[22] == b':' {
        let hours = parse_n(&bytes[20..22])?;
        let minutes = parse_n(&bytes[23..25])?;
        if hours > 23 || minutes > 59 {
            return None;
        }
        let offset = i64::from(hours) * 3_600 + i64::from(minutes) * 60;
        return Some(if bytes[19] == b'+' {
            instant - offset
        } else {
            instant + offset
        });
    }
    None
}

fn civil_seconds(bytes: &[u8]) -> Option<i64> {
    if bytes.len() != 19 || bytes[10] != b'T' {
        return None;
    }
    let year = parse_n(&bytes[0..4])?;
    let month = parse_n(&bytes[5..7])?;
    let day = parse_n(&bytes[8..10])?;
    let hour = parse_n(&bytes[11..13])?;
    let minute = parse_n(&bytes[14..16])?;
    let second = parse_n(&bytes[17..19])?;
    if bytes[4] != b'-' || bytes[7] != b'-' || bytes[13] != b':' || bytes[16] != b':' {
        return None;
    }
    if !(1..=12).contains(&month)
        || !(1..=days_in_month(year, month)).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    let days = days_from_civil(year, month, day)?;
    Some(days * 86_400 + hour as i64 * 3_600 + minute as i64 * 60 + second as i64)
}

fn days_in_month(year: i32, month: i32) -> i32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0) => 29,
        2 => 28,
        _ => 0,
    }
}

fn parse_n(bytes: &[u8]) -> Option<i32> {
    let mut value = 0i32;
    for byte in bytes {
        if !byte.is_ascii_digit() {
            return None;
        }
        value = value * 10 + i32::from(byte - b'0');
    }
    Some(value)
}

/// Howard Hinnant, days since 1970-01-01.
fn days_from_civil(year: i32, month: i32, day: i32) -> Option<i64> {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = (year - era * 400) as u64;
    let month_prime = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * month_prime + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year as u64;
    Some(era as i64 * 146_097 + day_of_era as i64 - 719_468)
}

fn civil_from_days(days: i64) -> (i32, i32, i32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let year_of_era = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let month_prime = (5 * doy + 2) / 153;
    let day = (doy - (153 * month_prime + 2) / 5 + 1) as i32;
    let month = if month_prime < 10 {
        month_prime as i32 + 3
    } else {
        month_prime as i32 - 9
    };
    let year = if month <= 2 {
        year_of_era + 1
    } else {
        year_of_era
    };
    (year as i32, month, day)
}

/// `left - right` as an exact decimal, or `None` when `right` is larger or either string is not a decimal.
pub fn decimal_sub(left: &str, right: &str) -> Option<String> {
    if !decimal_le(right, left) {
        return None;
    }
    let (left_int, left_frac) = split_decimal(left)?;
    let (right_int, right_frac) = split_decimal(right)?;
    let scale = left_frac.len().max(right_frac.len());
    let left_digits = scaled_digits(left_int, left_frac, scale);
    let right_digits = scaled_digits(right_int, right_frac, scale);
    Some(render_digits(
        &sub_digits(&left_digits, &right_digits),
        scale,
    ))
}

/// Multiply a non-negative decimal by an integer factor.
pub fn decimal_mul(value: &str, factor: u32) -> Option<String> {
    let (integer, fraction) = split_decimal(value)?;
    if factor == 0 {
        return Some(if fraction.is_empty() {
            "0".into()
        } else {
            format!("0.{}", "0".repeat(fraction.len()))
        });
    }
    let digits = scaled_digits(integer, fraction, fraction.len());
    let mut carry = 0u64;
    let mut out = Vec::new();
    for byte in digits.bytes().rev() {
        let product = u64::from(byte - b'0') * u64::from(factor) + carry;
        out.push(char::from(b'0' + (product % 10) as u8));
        carry = product / 10;
    }
    while carry > 0 {
        out.push(char::from(b'0' + (carry % 10) as u8));
        carry /= 10;
    }
    out.reverse();
    let text: String = out.into_iter().collect();
    Some(render_digits(&text, fraction.len()))
}

fn scaled_digits(integer: &str, fraction: &str, scale: usize) -> String {
    let mut digits = format!("{integer}{fraction}");
    digits.extend(std::iter::repeat_n('0', scale - fraction.len()));
    if digits.is_empty() {
        digits.push('0');
    }
    digits
}

fn sub_digits(left: &str, right: &str) -> String {
    let mut borrow = 0i32;
    let mut out = Vec::new();
    let width = left.len().max(right.len());
    for index in 0..width {
        let l = left
            .as_bytes()
            .get(left.len().wrapping_sub(index + 1))
            .map(|byte| i32::from(byte - b'0'))
            .unwrap_or(0);
        let r = right
            .as_bytes()
            .get(right.len().wrapping_sub(index + 1))
            .map(|byte| i32::from(byte - b'0'))
            .unwrap_or(0);
        let mut diff = l - r - borrow;
        if diff < 0 {
            diff += 10;
            borrow = 1;
        } else {
            borrow = 0;
        }
        out.push(char::from(b'0' + diff as u8));
    }
    out.reverse();
    let text: String = out.into_iter().collect();
    let trimmed = text.trim_start_matches('0');
    if trimmed.is_empty() {
        "0".into()
    } else {
        trimmed.into()
    }
}

fn render_digits(digits: &str, scale: usize) -> String {
    if scale == 0 {
        return digits.to_string();
    }
    let digits = if digits.len() <= scale {
        format!("{}{digits}", "0".repeat(scale - digits.len() + 1))
    } else {
        digits.to_string()
    };
    let split = digits.len() - scale;
    format!("{}.{}", &digits[..split], &digits[split..])
}

/// Exact decimal `<=` for money strings. No binary floating point.
pub fn decimal_le(left: &str, right: &str) -> bool {
    let Some((left_int, left_frac)) = split_decimal(left) else {
        return false;
    };
    let Some((right_int, right_frac)) = split_decimal(right) else {
        return false;
    };
    match cmp_digits(left_int, right_int) {
        std::cmp::Ordering::Less => true,
        std::cmp::Ordering::Greater => false,
        std::cmp::Ordering::Equal => {
            cmp_fraction(left_frac, right_frac) != std::cmp::Ordering::Greater
        }
    }
}

fn cmp_fraction(left: &str, right: &str) -> std::cmp::Ordering {
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

fn split_decimal(value: &str) -> Option<(&str, &str)> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
    {
        return None;
    }
    let mut parts = value.split('.');
    let integer = parts.next()?;
    let fraction = parts.next().unwrap_or("");
    if parts.next().is_some() || integer.is_empty() {
        return None;
    }
    Some((integer, fraction))
}

fn cmp_digits(left: &str, right: &str) -> std::cmp::Ordering {
    let left = left.trim_start_matches('0');
    let right = right.trim_start_matches('0');
    let left = if left.is_empty() { "0" } else { left };
    let right = if right.is_empty() { "0" } else { right };
    left.len().cmp(&right.len()).then_with(|| left.cmp(right))
}

#[cfg(test)]
mod tests {
    use super::{
        add_rfc3339_z, decimal_le, decimal_mul, decimal_sub, format_rfc3339_z, parse_rfc3339_z,
    };

    #[test]
    fn money_compares_as_exact_decimals() {
        assert!(decimal_le("0.3", "0.30"));
        assert!(decimal_le("0.30", "0.3"));
        assert!(decimal_le("1", "1.0000000000000001"));
        assert!(!decimal_le("1.0000000000000001", "1"));
        assert!(!decimal_le("20.01", "20.00"));
    }

    #[test]
    fn one_hour_is_3600_seconds() {
        let start = parse_rfc3339_z("2026-10-09T08:00:00Z").unwrap();
        let end = parse_rfc3339_z("2026-10-09T09:00:00Z").unwrap();
        assert_eq!(end - start, 3600);
    }

    #[test]
    fn formatting_round_trips_and_crosses_an_hour() {
        assert_eq!(format_rfc3339_z(0), "1970-01-01T00:00:00Z");
        let start = parse_rfc3339_z("2026-10-14T12:50:00Z").unwrap();
        assert_eq!(format_rfc3339_z(start), "2026-10-14T12:50:00Z");
        assert_eq!(
            add_rfc3339_z("2026-10-14T12:50:00Z", 1800).unwrap(),
            "2026-10-14T13:20:00Z"
        );
    }

    #[test]
    fn subtraction_and_multiplication_stay_exact() {
        assert_eq!(decimal_sub("5.00", "1.25").unwrap(), "3.75");
        assert_eq!(decimal_sub("1", "0.50").unwrap(), "0.50");
        assert_eq!(decimal_mul("1.50", 2).unwrap(), "3.00");
        assert!(decimal_sub("1.00", "1.01").is_none());
    }

    #[test]
    fn a_numeric_offset_is_the_same_instant_as_z() {
        let offset = parse_rfc3339_z("2026-10-09T08:30:00+02:00").unwrap();
        let zulu = parse_rfc3339_z("2026-10-09T06:30:00Z").unwrap();
        assert_eq!(offset, zulu);
    }
}
