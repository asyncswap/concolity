//! Mutation-based fuzzing over ABI values: The Fuzzing Book's `MutationFuzzer` (docs/FUZZ.md §5), with Solidity's
//! types as the alphabet instead of characters. An input is a fuzz test's decoded arguments; a mutation changes one
//! leaf value (or a few) and keeps every value inside its type, so the encoded calldata is always well-formed and
//! solc's decoder never rejects it. The dictionary is every constant the compiled code pushes (forge's trick): the
//! thresholds, magic selectors and limits a comparison is likely against.

use crate::coverage::Rng;
use alloy_dyn_abi::{DynSolType, DynSolValue};
use revm::primitives::{Address, I256, U256};
use std::collections::BTreeSet;

/// Constants the bytecode pushes (`PUSH1..PUSH32` data), deduplicated and capped: the values guards compare against.
#[derive(Debug, Default, Clone)]
pub struct Dictionary {
    pub words: Vec<U256>,
}

impl Dictionary {
    pub fn from_codes<'a>(codes: impl IntoIterator<Item = &'a [u8]>) -> Dictionary {
        let mut set: BTreeSet<U256> = BTreeSet::new();
        for code in codes {
            let mut pc = 0;
            while pc < code.len() {
                let op = code[pc];
                if (0x60..=0x7f).contains(&op) {
                    let n = (op - 0x5f) as usize;
                    if let Some(bytes) = code.get(pc + 1..pc + 1 + n) {
                        let v = U256::from_be_slice(bytes);
                        // Skip the trivial ones (the random generator has them) and jump targets (small values).
                        if v > U256::from(0xffff) {
                            set.insert(v);
                        }
                    }
                    pc += 1 + n;
                } else {
                    pc += 1;
                }
            }
            if set.len() > 8192 {
                break;
            }
        }
        Dictionary { words: set.into_iter().take(8192).collect() }
    }
}

fn mask(bits: usize) -> U256 {
    if bits >= 256 { U256::MAX } else { (U256::from(1) << bits) - U256::from(1) }
}

/// Values a comparison is likely against: 0, 1, 2, the type's edges, powers of two around them, small powers of ten.
fn interesting(bits: usize, rng: &mut Rng) -> U256 {
    let max = mask(bits);
    let half = if bits >= 2 { U256::from(1) << (bits - 1) } else { U256::from(1) };
    let picks = [
        U256::ZERO,
        U256::from(1),
        U256::from(2),
        max,
        max - U256::from(1),
        half,
        half - U256::from(1),
        half + U256::from(1),
        U256::from(1) << (bits / 2),
        U256::from(10).pow(U256::from(rng.next() % 30)),
        U256::from(1) << (rng.next() % bits.max(1) as u64),
    ];
    picks[(rng.next() % picks.len() as u64) as usize] & max
}

fn mutate_uint(v: U256, bits: usize, rng: &mut Rng, dict: &Dictionary) -> U256 {
    let max = mask(bits);
    let r = match rng.next() % 10 {
        0 => interesting(bits, rng),
        1 => v.wrapping_add(U256::from(1)),
        2 => v.wrapping_sub(U256::from(1)),
        3 => v.wrapping_add(U256::from(rng.next() % 1024)),
        4 => v.wrapping_sub(U256::from(rng.next() % 1024)),
        5 => v ^ (U256::from(1) << (rng.next() % bits.max(1) as u64)),
        6 => v << 1,
        7 => v >> 1,
        8 if !dict.words.is_empty() => dict.words[(rng.next() % dict.words.len() as u64) as usize],
        _ => rng.uint(bits),
    };
    r & max
}

/// One mutation of one value, inside its type.
fn mutate_value(v: &DynSolValue, rng: &mut Rng, dict: &Dictionary) -> DynSolValue {
    use DynSolValue as V;
    match v {
        V::Uint(x, bits) => V::Uint(mutate_uint(*x, *bits, rng, dict), *bits),
        V::Int(x, bits) => {
            let raw = mutate_uint(x.into_raw() & mask(*bits), *bits, rng, dict);
            // Sign-extend the low `bits` bits.
            let shift = 256 - *bits;
            V::Int(I256::from_raw(raw << shift).asr(shift), *bits)
        }
        V::Bool(b) => V::Bool(!b),
        V::Address(a) => V::Address(match rng.next() % 4 {
            0 => Address::ZERO,
            1 if !dict.words.is_empty() => Address::from_slice(&dict.words[(rng.next() % dict.words.len() as u64) as usize].to_be_bytes::<32>()[12..]),
            2 => Address::from_slice(&rng.word().to_be_bytes::<32>()[12..]),
            _ => {
                let mut w = a.0 .0;
                let i = (rng.next() % 20) as usize;
                w[i] ^= 1 << (rng.next() % 8);
                Address::from(w)
            }
        }),
        V::FixedBytes(w, n) => {
            let mut b = w.0;
            match rng.next() % 3 {
                0 => b[..*n].fill(0),
                1 => {
                    let i = (rng.next() % (*n).max(1) as u64) as usize;
                    b[i] ^= 1 << (rng.next() % 8);
                }
                _ => b[..*n].copy_from_slice(&rng.word().to_be_bytes::<32>()[..*n]),
            }
            V::FixedBytes(b.into(), *n)
        }
        V::Bytes(bytes) => V::Bytes(mutate_bytes(bytes, rng)),
        V::String(s) => V::String(String::from_utf8_lossy(&mutate_bytes(s.as_bytes(), rng)).into_owned()),
        V::Array(xs) => {
            let mut xs = xs.clone();
            match rng.next() % 4 {
                0 if !xs.is_empty() => {
                    xs.pop();
                }
                1 if !xs.is_empty() && xs.len() < 16 => {
                    let i = (rng.next() % xs.len() as u64) as usize;
                    let copy = xs[i].clone();
                    xs.push(copy);
                }
                2 if xs.is_empty() => {
                    if let Some(t) = v.as_type().and_then(|t| if let DynSolType::Array(e) = t { Some(*e) } else { None }) {
                        if let Some(x) = rng.value(&t) {
                            xs.push(x);
                        }
                    }
                }
                _ if !xs.is_empty() => {
                    let i = (rng.next() % xs.len() as u64) as usize;
                    xs[i] = mutate_value(&xs[i], rng, dict);
                }
                _ => {}
            }
            V::Array(xs)
        }
        V::FixedArray(xs) => {
            let mut xs = xs.clone();
            if !xs.is_empty() {
                let i = (rng.next() % xs.len() as u64) as usize;
                xs[i] = mutate_value(&xs[i], rng, dict);
            }
            V::FixedArray(xs)
        }
        V::Tuple(xs) | V::CustomStruct { tuple: xs, .. } => {
            let mut xs = xs.clone();
            if !xs.is_empty() {
                let i = (rng.next() % xs.len() as u64) as usize;
                xs[i] = mutate_value(&xs[i], rng, dict);
            }
            match v {
                V::CustomStruct { name, prop_names, .. } => V::CustomStruct { name: name.clone(), prop_names: prop_names.clone(), tuple: xs },
                _ => V::Tuple(xs),
            }
        }
        other => other.clone(),
    }
}

fn mutate_bytes(b: &[u8], rng: &mut Rng) -> Vec<u8> {
    let mut out = b.to_vec();
    match rng.next() % 4 {
        0 => out.truncate(out.len() / 2),
        1 if out.len() < 512 => out.extend((0..1 + rng.next() % 32).map(|_| rng.next() as u8)),
        2 if !out.is_empty() => {
            let i = (rng.next() % out.len() as u64) as usize;
            out[i] ^= 1 << (rng.next() % 8);
        }
        _ => {
            out.clear();
            out.extend((0..rng.next() % 64).map(|_| rng.next() as u8));
        }
    }
    out
}

/// A fuzz test's arguments, mutated: one leaf changed (two or three now and then).
pub(crate) fn mutate(args: &[DynSolValue], rng: &mut Rng, dict: &Dictionary) -> Vec<DynSolValue> {
    if args.is_empty() {
        return vec![];
    }
    let mut out = args.to_vec();
    let times = match rng.next() % 8 {
        0 => 3,
        1 | 2 => 2,
        _ => 1,
    };
    for _ in 0..times {
        let i = (rng.next() % out.len() as u64) as usize;
        out[i] = mutate_value(&out[i], rng, dict);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mutations_stay_inside_their_types() {
        let mut rng = Rng(7);
        let dict = Dictionary::from_codes([&[0x63u8, 0x5e, 0xed, 0x1e, 0x55, 0x60, 0x01][..]]);
        assert_eq!(dict.words, vec![U256::from(0x5eed1e55u64)], "a PUSH4 is a word; PUSH1 1 is trivial");
        let args = vec![DynSolValue::Uint(U256::from(5), 8), DynSolValue::Int(I256::try_from(-3).unwrap(), 16), DynSolValue::Bool(true), DynSolValue::Address(Address::ZERO), DynSolValue::FixedBytes(Default::default(), 4), DynSolValue::Bytes(vec![1, 2, 3])];
        let types: Vec<DynSolType> = args.iter().map(|a| a.as_type().unwrap()).collect();
        let mut hit_dict = false;
        for _ in 0..2000 {
            let m = mutate(&args, &mut rng, &dict);
            for (v, t) in m.iter().zip(&types) {
                assert_eq!(v.as_type().as_ref(), Some(t), "{v:?}");
                let enc = DynSolValue::Tuple(vec![v.clone()]).abi_encode_params();
                let back = DynSolType::Tuple(vec![t.clone()]).abi_decode_params(&enc).unwrap();
                assert_eq!(back.abi_encode_params(), enc, "round-trips as canonical ABI: {v:?}");
                if let DynSolValue::Uint(x, 8) = v {
                    assert!(*x <= U256::from(255));
                }
            }
            if m.iter().any(|v| matches!(v, DynSolValue::Uint(x, _) if *x == U256::from(0x55))) {
                hit_dict = true;
            }
        }
        assert!(hit_dict, "the dictionary word, masked to the type, comes up");
    }
}
