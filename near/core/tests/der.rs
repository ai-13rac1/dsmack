//! Tests of the strict DER parser. They need no fixtures.

use dsmack_attest_core::{der, Result};

fn err<T: std::fmt::Debug>(r: Result<T>) -> &'static str {
    r.expect_err("expected an error").0
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn utc(text: &str) -> Result<u64> {
    let mut b = vec![0x17, 13];
    b.extend_from_slice(text.as_bytes());
    let n = der::expect(&b, 0, b.len(), 0x17)?;
    der::utc(&b, &n)
}

#[test]
fn utc_matches_the_calendar_for_every_day_from_2020_to_2049() {
    for y in 2020..=2049i64 {
        for m in 1..=12i64 {
            let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
            let days = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][m as usize - 1];
            for d in 1..=days {
                let want = days_from_civil(y, m, d) * 86400 + 23 * 3600 + 59 * 60 + 58;
                let text = format!("{:02}{:02}{:02}235958Z", y - 2000, m, d);
                assert_eq!(utc(&text).unwrap() as i64, want, "{text}");
            }
            assert_eq!(err(utc(&format!("{:02}{:02}{:02}000000Z", y - 2000, m, days + 1))), "UTC day");
        }
    }
    assert_eq!(err(utc("191231235959Z")), "UTC range");
    assert_eq!(err(utc("500101000000Z")), "UTC range");
    assert_eq!(err(utc("260101240000Z")), "UTC range");
    assert_eq!(err(utc("26010100000aZ")), "UTC digit");
}

#[test]
fn lengths_use_the_shortest_form() {
    // 127 bytes: short form.
    let mut b = vec![0x04, 127];
    b.extend_from_slice(&[0; 127]);
    assert_eq!(der::expect(&b, 0, b.len(), 4).unwrap().end, 129);
    // 128 bytes: long form with one length byte.
    let mut b = vec![0x04, 0x81, 128];
    b.extend_from_slice(&[0; 128]);
    assert_eq!(der::expect(&b, 0, b.len(), 4).unwrap().end, 131);
    // A long form for a length below 128 is not minimal.
    let mut b = vec![0x04, 0x81, 127];
    b.extend_from_slice(&[0; 127]);
    assert_eq!(err(der::node(&b, 0, b.len())), "DER nonminimal length");
    // A leading zero length byte.
    let mut b = vec![0x04, 0x82, 0x00, 200];
    b.extend_from_slice(&[0; 200]);
    assert_eq!(err(der::node(&b, 0, b.len())), "DER leading length zero");
    // 256 bytes: two length bytes.
    let mut b = vec![0x04, 0x82, 0x01, 0x00];
    b.extend_from_slice(&[0; 256]);
    assert_eq!(der::expect(&b, 0, b.len(), 4).unwrap().end, 260);
    // Three length bytes are outside the profile.
    assert_eq!(err(der::node(&[0x04, 0x83, 0x01, 0x00, 0x00], 0, 5)), "DER length");
}

#[test]
fn nodes_must_fit_and_match() {
    assert_eq!(err(der::node(&[0x04], 0, 1)), "DER bounds");
    assert_eq!(err(der::node(&[0x04, 5, 0], 0, 3)), "DER truncated");
    assert_eq!(err(der::node(&[0x1f, 0], 0, 2)), "DER long tag");
    assert_eq!(err(der::expect(&[0x04, 0], 0, 2, 0x30)), "DER tag");
    // A node cannot reach past its parent.
    assert_eq!(err(der::node(&[0x04, 2, 0, 0], 0, 3)), "DER truncated");
}

#[test]
fn integers_are_canonical() {
    let int = |body: &[u8]| {
        let mut b = vec![0x02, body.len() as u8];
        b.extend_from_slice(body);
        let n = der::expect(&b, 0, b.len(), 2)?;
        der::integer::<4>(&b, &n)
    };
    assert_eq!(int(&[0x7f]).unwrap(), [0, 0, 0, 0x7f]);
    assert_eq!(int(&[0x00, 0x80]).unwrap(), [0, 0, 0, 0x80]);
    assert_eq!(err(int(&[0x80])), "DER negative integer");
    assert_eq!(err(int(&[0x00, 0x7f])), "DER padded integer");
    assert_eq!(err(int(&[1, 2, 3, 4, 5])), "DER integer width");
    assert_eq!(err(int(&[])), "DER integer");
}
