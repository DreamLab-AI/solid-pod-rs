//! JSS parity: `Range:` against an empty resource must produce
//! `416 Range Not Satisfiable`, not `412 Precondition Failed`.

use solid_pod_rs::ldp::{parse_range_header_v2, RangeOutcome};

#[test]
fn range_against_empty_body_returns_not_satisfiable() {
    let out = parse_range_header_v2(Some("bytes=0-99"), 0).unwrap();
    assert!(matches!(out, RangeOutcome::NotSatisfiable), "got {out:?}");
}

#[test]
fn range_full_resource_returns_partial() {
    let out = parse_range_header_v2(Some("bytes=0-99"), 1000).unwrap();
    match out {
        RangeOutcome::Partial(r) => {
            assert_eq!(r.start, 0);
            assert_eq!(r.end, 99);
        }
        _ => panic!("expected Partial, got {out:?}"),
    }
}

#[test]
fn range_no_header_returns_full() {
    let out = parse_range_header_v2(None, 1000).unwrap();
    assert!(matches!(out, RangeOutcome::Full), "got {out:?}");
}

#[test]
fn range_past_end_returns_not_satisfiable() {
    let out = parse_range_header_v2(Some("bytes=2000-3000"), 1000).unwrap();
    assert!(matches!(out, RangeOutcome::NotSatisfiable), "got {out:?}");
}

#[test]
fn range_suffix_request_returns_partial() {
    let out = parse_range_header_v2(Some("bytes=-200"), 1000).unwrap();
    match out {
        RangeOutcome::Partial(r) => {
            assert_eq!(r.start, 800);
            assert_eq!(r.end, 999);
        }
        _ => panic!("expected Partial, got {out:?}"),
    }
}
