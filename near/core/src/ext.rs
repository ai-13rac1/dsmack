//! Certificate extension walk shared by the intermediate and leaf parsers.

use crate::der::{self, Node};
use crate::error::{require, Result};

/// One extension: OID content bytes, the critical flag and the OCTET STRING content.
pub struct Extension<'a> {
    pub oid: &'a [u8],
    pub critical: bool,
    pub value: &'a [u8],
}

/// Walk the extension SEQUENCE `seq`. Reject more than 16 extensions, a repeated OID
/// and a malformed extension, then call `f` for each one.
pub fn walk<'a>(
    cert: &'a [u8],
    seq: &Node,
    mut f: impl FnMut(&Extension<'a>) -> Result<()>,
) -> Result<()> {
    let mut p = seq.body;
    let mut seen: Vec<&'a [u8]> = Vec::new();
    while p < seq.end {
        require!(seen.len() < 16, "too many extensions");
        let ext = der::expect(cert, p, seq.end, 0x30)?;
        p = ext.end;
        let oid = der::expect(cert, ext.body, ext.end, 6)?;
        let id = der::contents(cert, &oid);
        require!(!seen.contains(&id), "duplicate certificate extension");
        seen.push(id);
        let mut value = der::node(cert, oid.end, ext.end)?;
        let mut critical = false;
        if value.tag == 1 {
            require!(value.end - value.body == 1 && cert[value.body] == 0xff, "critical encoding");
            critical = true;
            value = der::node(cert, value.end, ext.end)?;
        }
        require!(value.tag == 4 && value.end == ext.end, "extension value");
        f(&Extension { oid: id, critical, value: der::contents(cert, &value) })?;
    }
    Ok(())
}
