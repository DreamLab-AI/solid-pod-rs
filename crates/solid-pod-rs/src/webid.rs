//! WebID profile document generation and validation.
//!
//! The embedded JSON-LD data island mirrors JSS
//! `src/webid/profile.js::generateProfileJsonLd` (commits cccd081 #320,
//! 01e12b0 #299): it carries both the legacy `solid:oidcIssuer` predicate
//! and the LWS 1.0 Controlled Identifier `service` array, plus
//! `foaf:isPrimaryTopicOf` / `schema:mainEntityOfPage` self-references.

use serde_json::{json, Value};

/// Render a WebID profile as an HTML document with embedded JSON-LD.
///
/// Omits `solid:oidcIssuer`. Prefer [`generate_webid_html_with_issuer`]
/// for Solid-OIDC flows.
pub fn generate_webid_html(pubkey: &str, name: Option<&str>, pod_base: &str) -> String {
    generate_webid_html_with_issuer(pubkey, name, pod_base, None)
}

/// Render a WebID profile with an optional Solid-OIDC issuer
/// advertised via `solid:oidcIssuer` and, when present, an LWS 1.0
/// `service` entry typed `lws:OpenIdProvider`.
pub fn generate_webid_html_with_issuer(
    pubkey: &str,
    name: Option<&str>,
    pod_base: &str,
    oidc_issuer: Option<&str>,
) -> String {
    let display_name = name.unwrap_or("Solid Pod User");
    let pod_url = format!("{pod_base}/pods/{pubkey}/");
    let webid = format!("{pod_base}/pods/{pubkey}/profile/card#me");
    // Document URL (WebID without fragment) — anchor for relative self
    // references and for the cid:service fragment id.
    let doc_url = webid.split('#').next().unwrap_or(&webid).to_string();

    let mut context = json!({
        "foaf": "http://xmlns.com/foaf/0.1/",
        "solid": "http://www.w3.org/ns/solid/terms#",
        "schema": "http://schema.org/",
        "cid": "https://www.w3.org/ns/cid/v1#",
        "lws": "https://www.w3.org/ns/lws#",
        "isPrimaryTopicOf": { "@id": "foaf:isPrimaryTopicOf", "@type": "@id" },
        "mainEntityOfPage": { "@id": "schema:mainEntityOfPage", "@type": "@id" },
        "service": { "@id": "cid:service", "@container": "@set" },
        "serviceEndpoint": { "@id": "cid:serviceEndpoint", "@type": "@id" }
    });
    // Keep context shape mutable in case future rows add more terms.
    let _ = context.as_object_mut();

    let mut body = json!({
        "@context": context,
        "@id": webid,
        "@type": "foaf:Person",
        "foaf:name": display_name,
        "foaf:isPrimaryTopicOf": "",
        "schema:mainEntityOfPage": "",
        "solid:account": pod_url,
        "solid:privateTypeIndex": format!("{pod_url}settings/privateTypeIndex"),
        "solid:publicTypeIndex": format!("{pod_url}settings/publicTypeIndex"),
        "schema:identifier": format!("did:nostr:{pubkey}")
    });

    if let Some(iss) = oidc_issuer {
        // Legacy Solid-OIDC predicate (kept for existing clients).
        body["solid:oidcIssuer"] = json!({ "@id": iss });
        // LWS 1.0 Controlled Identifier service entry.
        body["service"] = json!([{
            "@id": format!("{doc_url}#oidc"),
            "@type": "lws:OpenIdProvider",
            "serviceEndpoint": iss
        }]);
    }

    let body_json = serde_json::to_string_pretty(&body)
        .expect("serde_json::Value always serialises");

    format!(
        r#"<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>{display_name}</title>
  <script type="application/ld+json">
{body_json}
  </script>
</head>
<body>
  <h1>{display_name}</h1>
  <p>WebID: <a href="{webid}">{webid}</a></p>
  <p>Pod: <a href="{pod_url}">{pod_url}</a></p>
</body>
</html>"#
    )
}

/// Locate and parse the JSON-LD data island from a WebID HTML document.
fn parse_json_ld(data: &[u8]) -> Result<Option<Value>, String> {
    let text = std::str::from_utf8(data)
        .map_err(|_| "WebID profile must be valid UTF-8".to_string())?;
    let start = match text.find("application/ld+json") {
        Some(s) => s,
        None => return Ok(None),
    };
    let tag_end = match text[start..].find('>') {
        Some(e) => e,
        None => return Ok(None),
    };
    let json_start = start + tag_end + 1;
    let script_end = match text[json_start..].find("</script>") {
        Some(e) => e,
        None => return Ok(None),
    };
    let json_str = text[json_start..json_start + script_end].trim();
    let value: Value = serde_json::from_str(json_str)
        .map_err(|e| format!("WebID JSON-LD parse error: {e}"))?;
    Ok(Some(value))
}

/// Follow-your-nose discovery — extract `solid:oidcIssuer` from a
/// WebID HTML document. Returns `Ok(None)` when the profile does not
/// advertise an issuer.
pub fn extract_oidc_issuer(data: &[u8]) -> Result<Option<String>, String> {
    let value = match parse_json_ld(data)? {
        Some(v) => v,
        None => return Ok(None),
    };
    let issuer = value.get("solid:oidcIssuer").or_else(|| {
        value.get("http://www.w3.org/ns/solid/terms#oidcIssuer")
    });
    match issuer {
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(Value::Object(m)) => {
            if let Some(Value::String(s)) = m.get("@id") {
                Ok(Some(s.clone()))
            } else {
                Ok(None)
            }
        }
        _ => Ok(None),
    }
}

/// LWS 1.0 Controlled Identifier discovery — return the
/// `serviceEndpoint` of the first `service` entry whose `@type` is
/// `lws:OpenIdProvider` (or the fully-expanded IRI). Mirrors the shape
/// of [`extract_oidc_issuer`]; returns `Ok(None)` when absent.
pub fn extract_cid_openid_provider(data: &[u8]) -> Result<Option<String>, String> {
    let value = match parse_json_ld(data)? {
        Some(v) => v,
        None => return Ok(None),
    };
    let service = value
        .get("service")
        .or_else(|| value.get("cid:service"))
        .or_else(|| value.get("https://www.w3.org/ns/cid/v1#service"));
    let arr = match service {
        Some(Value::Array(a)) => a,
        _ => return Ok(None),
    };
    for entry in arr {
        let Some(obj) = entry.as_object() else {
            continue;
        };
        let ty = obj.get("@type");
        let matches = match ty {
            Some(Value::String(s)) => {
                s == "lws:OpenIdProvider" || s == "https://www.w3.org/ns/lws#OpenIdProvider"
            }
            Some(Value::Array(ts)) => ts.iter().any(|t| {
                matches!(
                    t.as_str(),
                    Some("lws:OpenIdProvider")
                        | Some("https://www.w3.org/ns/lws#OpenIdProvider")
                )
            }),
            _ => false,
        };
        if !matches {
            continue;
        }
        let endpoint = obj
            .get("serviceEndpoint")
            .or_else(|| obj.get("cid:serviceEndpoint"))
            .or_else(|| obj.get("https://www.w3.org/ns/cid/v1#serviceEndpoint"));
        match endpoint {
            Some(Value::String(s)) => return Ok(Some(s.clone())),
            Some(Value::Object(m)) => {
                if let Some(Value::String(s)) = m.get("@id") {
                    return Ok(Some(s.clone()));
                }
            }
            _ => {}
        }
    }
    Ok(None)
}

/// Validate that a byte slice is a well-formed WebID profile.
pub fn validate_webid_html(data: &[u8]) -> Result<(), String> {
    let text = std::str::from_utf8(data)
        .map_err(|_| "WebID profile must be valid UTF-8".to_string())?;
    if !text.contains("application/ld+json") {
        return Err(
            "WebID profile must contain a <script type=\"application/ld+json\"> block".to_string(),
        );
    }
    // parse_json_ld surfaces syntactic errors.
    parse_json_ld(data)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn json_ld_body(html: &str) -> serde_json::Value {
        let start = html.find("application/ld+json").expect("ld+json tag");
        let tag_end = html[start..].find('>').expect("script >");
        let body_start = start + tag_end + 1;
        let body_end = html[body_start..].find("</script>").expect("/script");
        let body = html[body_start..body_start + body_end].trim();
        serde_json::from_str(body).expect("body parses")
    }

    #[test]
    fn contains_pubkey() {
        let html = generate_webid_html("abc123", None, "https://pods.example.com");
        assert!(html.contains("abc123"));
        assert!(html.contains("did:nostr:abc123"));
    }

    #[test]
    fn validate_accepts_valid() {
        let html = generate_webid_html("abc", Some("Alice"), "https://pods.example.com");
        assert!(validate_webid_html(html.as_bytes()).is_ok());
    }

    #[test]
    fn validate_rejects_missing_jsonld() {
        let html = "<!DOCTYPE html><html><body>no ld+json</body></html>";
        assert!(validate_webid_html(html.as_bytes()).is_err());
    }

    #[test]
    fn generate_with_issuer_embeds_oidc_triple() {
        let html = generate_webid_html_with_issuer(
            "abc",
            Some("Alice"),
            "https://pods.example.com",
            Some("https://op.example"),
        );
        assert!(html.contains("solid:oidcIssuer"));
        assert!(html.contains("https://op.example"));
    }

    #[test]
    fn extract_oidc_issuer_returns_issuer_id() {
        let html = generate_webid_html_with_issuer(
            "abc",
            Some("Alice"),
            "https://pods.example.com",
            Some("https://op.example"),
        );
        let iss = extract_oidc_issuer(html.as_bytes()).unwrap();
        assert_eq!(iss.as_deref(), Some("https://op.example"));
    }

    #[test]
    fn extract_oidc_issuer_absent_returns_none() {
        let html =
            generate_webid_html_with_issuer("abc", Some("Alice"), "https://p", None);
        let iss = extract_oidc_issuer(html.as_bytes()).unwrap();
        assert!(iss.is_none());
    }

    // --- Parity rows 154/155/165 ---------------------------------------

    #[test]
    fn emits_cid_service_when_issuer_present() {
        let html = generate_webid_html_with_issuer(
            "abc",
            Some("Alice"),
            "https://pods.example.com",
            Some("https://op.example"),
        );
        // Context namespaces are present.
        assert!(
            html.contains("https://www.w3.org/ns/cid/v1#"),
            "cid namespace missing"
        );
        assert!(
            html.contains("https://www.w3.org/ns/lws#"),
            "lws namespace missing"
        );
        // Service entry with LWS OpenIdProvider type.
        assert!(
            html.contains("lws:OpenIdProvider"),
            "lws:OpenIdProvider type missing"
        );
        // Service @id resolves against document URL (fragment #oidc).
        assert!(
            html.contains("https://pods.example.com/pods/abc/profile/card#oidc"),
            "service @id fragment missing"
        );
    }

    #[test]
    fn omits_cid_service_when_no_issuer() {
        let html =
            generate_webid_html_with_issuer("abc", Some("Alice"), "https://p", None);
        let body = json_ld_body(&html);
        assert!(
            body.get("service").is_none(),
            "service array must be absent without issuer"
        );
        assert!(
            !html.contains("lws:OpenIdProvider"),
            "OpenIdProvider must not leak when issuer absent"
        );
    }

    #[test]
    fn emits_primary_topic_of_and_main_entity_of_page() {
        let html = generate_webid_html_with_issuer(
            "abc",
            Some("Alice"),
            "https://pods.example.com",
            None,
        );
        let body = json_ld_body(&html);
        assert_eq!(
            body.get("foaf:isPrimaryTopicOf").and_then(|v| v.as_str()),
            Some(""),
            "foaf:isPrimaryTopicOf must be empty string (relative self-ref)"
        );
        assert_eq!(
            body.get("schema:mainEntityOfPage").and_then(|v| v.as_str()),
            Some(""),
            "schema:mainEntityOfPage must be empty string (relative self-ref)"
        );
        // Context must declare both predicates.
        let ctx = body.get("@context").expect("@context");
        assert!(ctx.get("isPrimaryTopicOf").is_some());
        assert!(ctx.get("mainEntityOfPage").is_some());
    }

    #[test]
    fn extract_cid_openid_provider_returns_endpoint() {
        let html = generate_webid_html_with_issuer(
            "abc",
            Some("Alice"),
            "https://pods.example.com",
            Some("https://op.example"),
        );
        let endpoint = extract_cid_openid_provider(html.as_bytes()).unwrap();
        assert_eq!(endpoint.as_deref(), Some("https://op.example"));
    }

    #[test]
    fn extract_cid_openid_provider_absent_returns_none() {
        let html =
            generate_webid_html_with_issuer("abc", Some("Alice"), "https://p", None);
        let endpoint = extract_cid_openid_provider(html.as_bytes()).unwrap();
        assert!(endpoint.is_none());
    }

    #[test]
    fn json_ld_body_is_valid_json() {
        // Regression guard against hand-escaping: whatever issuer/name we
        // feed in, the embedded body must parse with serde_json.
        for issuer in [None, Some("https://op.example/path?q=1&x=2")] {
            let html = generate_webid_html_with_issuer(
                "abc",
                Some(r#"Alice "Quoted" O'Neil"#),
                "https://pods.example.com",
                issuer,
            );
            let start = html
                .find("application/ld+json")
                .expect("ld+json tag present");
            let tag_end = html[start..].find('>').expect("script open >");
            let body_start = start + tag_end + 1;
            let body_end = html[body_start..]
                .find("</script>")
                .expect("script close");
            let body = html[body_start..body_start + body_end].trim();
            serde_json::from_str::<serde_json::Value>(body).unwrap_or_else(|e| {
                panic!("embedded JSON-LD failed to parse: {e}\n----\n{body}\n----")
            });
        }
    }
}
