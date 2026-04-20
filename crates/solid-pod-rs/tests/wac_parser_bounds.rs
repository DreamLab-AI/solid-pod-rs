//! WAC parser DoS bounds: byte cap on Turtle, depth cap on JSON-LD.
//!
//! The parser handles untrusted ACL documents that may be uploaded by
//! external agents. Without bounds a pathological document can either
//! exhaust memory (oversize Turtle) or blow the stack (deeply nested
//! JSON-LD). JSS's `n3` parser is similarly bounded; parity here is a
//! security property, not just a feature.

use solid_pod_rs::error::PodError;
use solid_pod_rs::wac::{parse_jsonld_acl, parse_turtle_acl, MAX_ACL_BYTES, MAX_ACL_JSON_DEPTH};

#[test]
fn wac_acl_recursion_bombs_rejected() {
    // 200-level nested JSON-LD document. Each wrapper carries a list
    // to keep the shape vaguely ACL-like while exceeding depth.
    let depth = 200;
    let mut s = String::new();
    for _ in 0..depth {
        s.push('{');
        s.push_str("\"@graph\":[");
    }
    for _ in 0..depth {
        s.push(']');
        s.push('}');
    }
    let err = parse_jsonld_acl(s.as_bytes()).unwrap_err();
    assert!(matches!(err, PodError::BadRequest(_) | PodError::AclParse(_)), "got {err:?}");
}

#[test]
fn wac_turtle_acl_oversize_rejected() {
    // ~10 MiB of whitespace — sufficient to exceed the 1 MiB cap.
    let big = " ".repeat(10 * 1024 * 1024);
    let err = parse_turtle_acl(&big).unwrap_err();
    assert!(matches!(err, PodError::BadRequest(_) | PodError::AclParse(_)), "got {err:?}");
}

#[test]
fn wac_acl_depth_within_limit_succeeds() {
    // A flat JSON-LD ACL with typical nesting.
    let body: &[u8] = br##"
        {
          "@context": "http://www.w3.org/ns/auth/acl",
          "@graph": [
            {
              "@id": "#owner",
              "@type": "acl:Authorization",
              "acl:agent": { "@id": "https://alice.example/card#me" },
              "acl:mode": { "@id": "acl:Read" }
            }
          ]
        }
    "##;
    let doc = parse_jsonld_acl(body).unwrap();
    let g = doc.graph.as_ref().unwrap();
    assert_eq!(g.len(), 1);
}

#[test]
fn wac_turtle_acl_under_limit_succeeds() {
    let ttl = r#"
        @prefix acl: <http://www.w3.org/ns/auth/acl#> .
        @prefix foaf: <http://xmlns.com/foaf/0.1/> .
        <#pub>
          a acl:Authorization ;
          acl:agentClass foaf:Agent ;
          acl:accessTo <./> ;
          acl:mode acl:Read .
    "#;
    let doc = parse_turtle_acl(ttl).unwrap();
    assert!(doc.graph.as_ref().is_some_and(|g| !g.is_empty()));
}

#[test]
fn wac_constants_are_sensible() {
    assert_eq!(MAX_ACL_BYTES, 1_048_576);
    assert_eq!(MAX_ACL_JSON_DEPTH, 32);
}
