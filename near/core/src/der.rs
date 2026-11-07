//! Bounded canonical DER for the supported Apple certificate profile.
//! Port of `StrictDER.sol`.

use crate::error::{require, Result};

#[derive(Debug, Clone, Copy)]
pub struct Node {
    pub start: usize,
    pub body: usize,
    pub end: usize,
    pub tag: u8,
}

pub fn node(b: &[u8], at: usize, limit: usize) -> Result<Node> {
    require!(limit <= b.len() && at.checked_add(2).is_some_and(|v| v <= limit), "DER bounds");
    let tag = b[at];
    require!(tag & 31 != 31, "DER long tag");
    let mut len = b[at + 1] as usize;
    let mut body = at + 2;
    if len >= 128 {
        let count = len & 127;
        require!(count > 0 && count <= 2 && body + count <= limit, "DER length");
        require!(b[body] != 0, "DER leading length zero");
        len = 0;
        for _ in 0..count {
            len = (len << 8) | b[body] as usize;
            body += 1;
        }
        require!(len >= 128, "DER nonminimal length");
    }
    let end = body + len;
    require!(end <= limit, "DER truncated");
    Ok(Node { start: at, body, end, tag })
}

pub fn expect(b: &[u8], at: usize, limit: usize, tag: u8) -> Result<Node> {
    let n = node(b, at, limit)?;
    require!(n.tag == tag, "DER tag");
    Ok(n)
}

pub fn contents<'a>(b: &'a [u8], n: &Node) -> &'a [u8] {
    &b[n.body..n.end]
}

pub fn encoded<'a>(b: &'a [u8], n: &Node) -> &'a [u8] {
    &b[n.start..n.end]
}

/// A DER INTEGER as a big-endian value, left-padded with zeros to `N` bytes.
pub fn integer<const N: usize>(b: &[u8], n: &Node) -> Result<[u8; N]> {
    require!(n.tag == 2 && n.end > n.body, "DER integer");
    let mut start = n.body;
    require!(b[start] < 128, "DER negative integer");
    if b[start] == 0 && n.end - start > 1 {
        require!(b[start + 1] >= 128, "DER padded integer");
        start += 1;
    }
    require!(n.end - start <= N, "DER integer width");
    let mut value = [0u8; N];
    value[N - (n.end - start)..].copy_from_slice(&b[start..n.end]);
    Ok(value)
}

/// A UTCTime `YYMMDDHHMMSSZ` as Unix seconds. Years 2020 to 2049 only.
pub fn utc(b: &[u8], n: &Node) -> Result<u64> {
    require!(n.tag == 0x17 && n.end - n.body == 13 && b[n.end - 1] == 0x5a, "UTC profile");
    let mut v = [0u64; 6];
    for (i, slot) in v.iter_mut().enumerate() {
        let a = b[n.body + 2 * i];
        let c = b[n.body + 2 * i + 1];
        require!((48..=57).contains(&a) && (48..=57).contains(&c), "UTC digit");
        *slot = (a as u64 - 48) * 10 + c as u64 - 48;
    }
    let year = 2000 + v[0];
    require!(
        (2020..=2049).contains(&year) && (1..=12).contains(&v[1]) && v[3] < 24 && v[4] < 60 && v[5] < 60,
        "UTC range"
    );
    let mut days_in = [31u64, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    if year % 4 == 0 {
        days_in[1] = 29;
    }
    require!(v[2] >= 1 && v[2] <= days_in[v[1] as usize - 1], "UTC day");
    let mut total_days = 0u64;
    for y in 1970..year {
        total_days += if y % 4 == 0 { 366 } else { 365 };
    }
    for m in 1..v[1] {
        total_days += days_in[m as usize - 1];
    }
    total_days += v[2] - 1;
    Ok(total_days * 86400 + v[3] * 3600 + v[4] * 60 + v[5])
}
