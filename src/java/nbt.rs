//! Minimal network-NBT reader whose only job is to flatten a Java text component to plain text.
//!
//! Since 1.20.3 text components travel as *network NBT* (no root name). A component is either a
//! string tag or a compound with `text` / `translate` and an `extra` list. Colors and formatting are
//! dropped; translation keys are shown as-is (no client-side language files here).
//!
//! Bounded on purpose: depth and total tag count are capped so crafted NBT cannot blow the stack
//! or the heap.

use crate::util::{Error, Reader, Result};

const MAX_DEPTH: usize = 32;
const MAX_TAGS: usize = 4096;

enum Tag {
    Text(String),
    Compound(Vec<(String, Tag)>),
    List(Vec<Tag>),
    Other,
}

struct Budget {
    tags: usize,
}

fn read_name(r: &mut Reader) -> Result<String> {
    let len = r.u16_be()? as usize;
    Ok(String::from_utf8_lossy(r.take(len)?).into_owned())
}

fn skip(r: &mut Reader, n: usize) -> Result<()> {
    r.take(n).map(|_| ())
}

fn read_payload(r: &mut Reader, ty: u8, depth: usize, budget: &mut Budget) -> Result<Tag> {
    if depth > MAX_DEPTH {
        return Err(Error::Limit("nbt depth"));
    }
    budget.tags += 1;
    if budget.tags > MAX_TAGS {
        return Err(Error::Limit("nbt tag count"));
    }
    match ty {
        1 => skip(r, 1).map(|_| Tag::Other),
        2 => skip(r, 2).map(|_| Tag::Other),
        3 | 5 => skip(r, 4).map(|_| Tag::Other),
        4 | 6 => skip(r, 8).map(|_| Tag::Other),
        7 => {
            let n = r.i32_be()?;
            skip(r, usize::try_from(n).map_err(|_| Error::Invalid("nbt array length"))?)?;
            Ok(Tag::Other)
        }
        8 => Ok(Tag::Text(read_name(r)?)),
        9 => {
            let elem = r.u8()?;
            let n = usize::try_from(r.i32_be()?).map_err(|_| Error::Invalid("nbt list length"))?;
            if n > MAX_TAGS {
                return Err(Error::Limit("nbt list length"));
            }
            let mut items = Vec::new();
            for _ in 0..n {
                items.push(read_payload(r, elem, depth + 1, budget)?);
            }
            Ok(Tag::List(items))
        }
        10 => {
            let mut fields = Vec::new();
            loop {
                let t = r.u8()?;
                if t == 0 {
                    break;
                }
                let name = read_name(r)?;
                fields.push((name, read_payload(r, t, depth + 1, budget)?));
            }
            Ok(Tag::Compound(fields))
        }
        11 | 12 => {
            let n = usize::try_from(r.i32_be()?).map_err(|_| Error::Invalid("nbt array length"))?;
            let width = if ty == 11 { 4 } else { 8 };
            skip(r, n.checked_mul(width).ok_or(Error::Limit("nbt array length"))?)?;
            Ok(Tag::Other)
        }
        _ => Err(Error::Invalid("unknown nbt tag type")),
    }
}

fn flatten(tag: &Tag, out: &mut String) {
    match tag {
        Tag::Text(s) => out.push_str(s),
        Tag::List(items) => items.iter().for_each(|t| flatten(t, out)),
        Tag::Compound(fields) => {
            let get = |k: &str| fields.iter().find(|(n, _)| n == k).map(|(_, t)| t);
            match (get("text"), get("translate")) {
                (Some(t), _) | (None, Some(t)) => flatten(t, out),
                _ => {}
            }
            if let Some(extra) = get("extra") {
                flatten(extra, out);
            }
        }
        Tag::Other => {}
    }
}

/// Read one network-NBT text component from `r` and return its plain text.
pub fn read_component_text(r: &mut Reader) -> Result<String> {
    let ty = r.u8()?;
    let tag = read_payload(r, ty, 0, &mut Budget { tags: 0 })?;
    let mut out = String::new();
    flatten(&tag, &mut out);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn string_tag(s: &str) -> Vec<u8> {
        let mut v = (s.len() as u16).to_be_bytes().to_vec();
        v.extend_from_slice(s.as_bytes());
        v
    }

    #[test]
    fn plain_string_component() {
        let mut data = vec![8u8];
        data.extend(string_tag("hello"));
        assert_eq!(read_component_text(&mut Reader::new(&data)).unwrap(), "hello");
    }

    #[test]
    fn compound_with_extra() {
        // {text:"a", extra:[ "b", {text:"c"} ]}
        let mut d = vec![10u8];
        d.push(8);
        d.extend(string_tag("text"));
        d.extend(string_tag("a"));
        d.push(9);
        d.extend(string_tag("extra"));
        d.push(8); // list of strings? mixed lists are illegal NBT; use compounds below instead
        d.extend(1i32.to_be_bytes());
        d.extend(string_tag("b"));
        d.push(0);
        assert_eq!(read_component_text(&mut Reader::new(&d)).unwrap(), "ab");
    }

    #[test]
    fn deeply_nested_input_is_rejected() {
        // Root compound, then 64 times: "compound field named x" opening another compound.
        let mut d = vec![10u8];
        for _ in 0..64 {
            d.extend([10u8, 0, 1, b'x']);
        }
        assert!(read_component_text(&mut Reader::new(&d)).is_err());
    }
}
