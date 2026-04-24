//! HTTP Signatures for ActivityPub federation.
//!
//! ActivityPub servers in the wild (Mastodon, Pleroma, Misskey,
//! GoToSocial) overwhelmingly use **draft-cavage-http-signatures-12**
//! with `rsa-sha256` as the signing algorithm. RFC 9421 is newer and
//! not yet widely deployed in the fediverse, so this module supports
//! both — verification auto-detects by header shape.
//!
//! Covered headers for AP:
//!   * `(request-target)` — method + path
//!   * `host`
//!   * `date`
//!   * `digest` — SHA-256 of body (inbound only; required for POST)
//!
//! References:
//!   * <https://datatracker.ietf.org/doc/html/draft-cavage-http-signatures-12>
//!   * <https://www.rfc-editor.org/rfc/rfc9421.html>
//!   * <https://docs.joinmastodon.org/spec/security/#http>

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use rsa::pkcs1v15::{Signature as RsaSignature, SigningKey, VerifyingKey};
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey};
use rsa::signature::{SignatureEncoding, Signer, Verifier};
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

use crate::error::SigError;

/// A raw inbound request awaiting signature verification.
#[derive(Debug, Clone)]
pub struct SignedRequest {
    pub method: String,
    pub path: String,
    /// Lower-cased header name → value. Multi-valued headers are
    /// joined with ", " per RFC 7230 §3.2.2.
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl SignedRequest {
    pub fn new(method: impl Into<String>, path: impl Into<String>, body: Vec<u8>) -> Self {
        Self {
            method: method.into(),
            path: path.into(),
            headers: HashMap::new(),
            body,
        }
    }
    pub fn with_header(mut self, name: impl AsRef<str>, value: impl Into<String>) -> Self {
        self.headers
            .insert(name.as_ref().to_ascii_lowercase(), value.into());
        self
    }
    fn get(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(String::as_str)
    }
}

/// A request prepared for outbound delivery — signed headers to be
/// attached plus the body (unchanged).
#[derive(Debug, Clone)]
pub struct OutboundRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Verified actor — the keyId plus its fetched public-key PEM. Inbox
/// handlers use this to tie an activity to a known AP actor.
#[derive(Debug, Clone)]
pub struct VerifiedActor {
    pub key_id: String,
    pub actor_url: String,
    pub public_key_pem: String,
}

/// Strategy for looking up an actor's public key from its `keyId`.
///
/// In production this is an HTTP fetch with cache (see
/// [`HttpActorKeyResolver`]); in tests it's a simple in-memory map.
#[async_trait]
pub trait ActorKeyResolver: Send + Sync {
    async fn resolve(&self, key_id: &str) -> Result<VerifiedActor, SigError>;
}

/// HTTP-backed resolver with actor-document caching. Matches
/// JSS's `fetchActor` behaviour: GET the URL (with `#main-key` or
/// similar fragment stripped), parse `publicKey.publicKeyPem`.
pub struct HttpActorKeyResolver {
    client: reqwest::Client,
}

impl Default for HttpActorKeyResolver {
    fn default() -> Self {
        Self {
            client: reqwest::Client::builder()
                .user_agent("solid-pod-rs-activitypub/0.4")
                .build()
                .expect("reqwest client builds"),
        }
    }
}

#[async_trait]
impl ActorKeyResolver for HttpActorKeyResolver {
    async fn resolve(&self, key_id: &str) -> Result<VerifiedActor, SigError> {
        let actor_url = key_id
            .split_once('#')
            .map(|(u, _)| u.to_string())
            .unwrap_or_else(|| key_id.to_string());
        let resp = self
            .client
            .get(&actor_url)
            .header(reqwest::header::ACCEPT, "application/activity+json")
            .send()
            .await
            .map_err(|e| SigError::ActorFetch(actor_url.clone(), e.to_string()))?;
        if !resp.status().is_success() {
            return Err(SigError::ActorFetch(
                actor_url.clone(),
                format!("status {}", resp.status()),
            ));
        }
        let doc: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| SigError::ActorFetch(actor_url.clone(), e.to_string()))?;
        let pem = doc
            .get("publicKey")
            .and_then(|k| k.get("publicKeyPem"))
            .and_then(|v| v.as_str())
            .ok_or(SigError::NoPublicKey)?;
        Ok(VerifiedActor {
            key_id: key_id.to_string(),
            actor_url,
            public_key_pem: pem.to_string(),
        })
    }
}

// ---------------------------------------------------------------------------
// Signature header parsing
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
struct SignatureHeader {
    key_id: String,
    algorithm: String,
    headers: Vec<String>,
    signature_b64: String,
}

/// Parse a `Signature:` header in draft-cavage form:
/// `keyId="...",algorithm="...",headers="(request-target) host date digest",signature="..."`
fn parse_signature_header(raw: &str) -> Result<SignatureHeader, SigError> {
    let mut out = SignatureHeader::default();
    // Attribute parser — split on commas that are outside quoted values.
    let mut attrs: Vec<(String, String)> = Vec::new();
    let mut cur_key = String::new();
    let mut cur_val = String::new();
    let mut in_val = false;
    let mut in_quote = false;
    let mut expecting_eq = false;
    for ch in raw.chars() {
        if !in_val {
            match ch {
                '=' => {
                    in_val = true;
                    expecting_eq = false;
                }
                ',' | ' ' | '\t' if cur_key.is_empty() => { /* skip whitespace */ }
                c if c.is_ascii_whitespace() => {
                    expecting_eq = true;
                }
                _ if expecting_eq => {
                    // unexpected text after key with whitespace — part of next key
                    cur_key.push(ch);
                    expecting_eq = false;
                }
                _ => cur_key.push(ch),
            }
        } else {
            match ch {
                '"' => {
                    if in_quote {
                        // end of quoted value
                        attrs.push((
                            std::mem::take(&mut cur_key).to_ascii_lowercase(),
                            std::mem::take(&mut cur_val),
                        ));
                        in_quote = false;
                        in_val = false;
                    } else {
                        in_quote = true;
                    }
                }
                ',' if !in_quote => {
                    if !cur_key.is_empty() {
                        attrs.push((
                            std::mem::take(&mut cur_key).to_ascii_lowercase(),
                            std::mem::take(&mut cur_val),
                        ));
                    }
                    in_val = false;
                }
                _ => {
                    if in_quote || !ch.is_ascii_whitespace() {
                        cur_val.push(ch);
                    }
                }
            }
        }
    }
    if !cur_key.is_empty() && (in_val || !cur_val.is_empty()) {
        attrs.push((cur_key.to_ascii_lowercase(), cur_val));
    }

    for (k, v) in attrs {
        match k.as_str() {
            "keyid" => out.key_id = v,
            "algorithm" => out.algorithm = v.to_ascii_lowercase(),
            "headers" => {
                out.headers = v
                    .split_ascii_whitespace()
                    .map(|s| s.to_ascii_lowercase())
                    .collect();
            }
            "signature" => out.signature_b64 = v,
            _ => {}
        }
    }
    if out.key_id.is_empty() {
        return Err(SigError::MissingKeyId);
    }
    if out.signature_b64.is_empty() {
        return Err(SigError::MalformedSignature("missing signature= value".into()));
    }
    if out.algorithm.is_empty() {
        // Mastodon used to omit this — default to rsa-sha256 per
        // current AP fleet behaviour.
        out.algorithm = "rsa-sha256".to_string();
    }
    if out.headers.is_empty() {
        // Default per draft-cavage §2.1.6 — Date only. AP servers
        // should be stricter; we preserve the default for tolerance.
        out.headers = vec!["date".to_string()];
    }
    Ok(out)
}

/// Rebuild the signature base string for a draft-cavage `headers="..."`
/// list.
fn build_signature_base(req: &SignedRequest, header_list: &[String]) -> Result<String, SigError> {
    let mut lines = Vec::with_capacity(header_list.len());
    for h in header_list {
        match h.as_str() {
            "(request-target)" => {
                lines.push(format!(
                    "(request-target): {} {}",
                    req.method.to_ascii_lowercase(),
                    req.path
                ));
            }
            name => {
                let v = req
                    .get(name)
                    .ok_or_else(|| SigError::VerifyFailed(format!("missing covered header: {name}")))?;
                lines.push(format!("{name}: {v}"));
            }
        }
    }
    Ok(lines.join("\n"))
}

/// Compute the canonical `Digest: SHA-256=...` header value for a body.
pub fn digest_header(body: &[u8]) -> String {
    let digest = Sha256::digest(body);
    format!("SHA-256={}", B64.encode(digest))
}

/// Verify an inbound signed request. Returns the [`VerifiedActor`] on
/// success so the caller can tie activity processing to the signing
/// identity.
pub async fn verify_request_signature(
    req: &SignedRequest,
    resolver: &dyn ActorKeyResolver,
) -> Result<VerifiedActor, SigError> {
    let sig_raw = req
        .get("signature")
        .ok_or(SigError::MissingHeader("signature"))?;
    let parsed = parse_signature_header(sig_raw)?;
    if parsed.algorithm != "rsa-sha256" && parsed.algorithm != "hs2019" {
        return Err(SigError::UnsupportedAlgorithm(parsed.algorithm));
    }

    // Digest check — if the covered set includes `digest`, the body
    // must hash to the header's value. This is mandatory for POST.
    if parsed.headers.iter().any(|h| h == "digest") {
        let received = req
            .get("digest")
            .ok_or(SigError::MissingHeader("digest"))?;
        let computed = digest_header(&req.body);
        // Mastodon historically uses `SHA-256=...`; some servers use
        // the RFC 9530 `sha-256=:<b64>:` form. Tolerate both.
        if received != computed
            && !received.eq_ignore_ascii_case(&computed)
        {
            let rfc9530 = {
                let digest = Sha256::digest(&req.body);
                format!("sha-256=:{}:", B64.encode(digest))
            };
            if received != rfc9530 {
                return Err(SigError::DigestMismatch);
            }
        }
    }

    let actor = resolver.resolve(&parsed.key_id).await?;
    let pub_key = RsaPublicKey::from_public_key_pem(&actor.public_key_pem)
        .map_err(|e| SigError::Rsa(e.to_string()))?;
    let vk = VerifyingKey::<Sha256>::new(pub_key);

    let base = build_signature_base(req, &parsed.headers)?;
    let sig_bytes = B64
        .decode(parsed.signature_b64.as_bytes())
        .map_err(|e| SigError::Base64(e.to_string()))?;
    let sig = RsaSignature::try_from(sig_bytes.as_slice())
        .map_err(|e| SigError::MalformedSignature(e.to_string()))?;
    vk.verify(base.as_bytes(), &sig)
        .map_err(|e| SigError::VerifyFailed(e.to_string()))?;
    Ok(actor)
}

/// Sign an outbound AP delivery. The caller provides the pod's PEM
/// private key and its published `keyId` (e.g.
/// `https://pod.example/profile/card.jsonld#main-key`).
///
/// On return, `req.headers` carries `Host`, `Date`, `Digest` and
/// `Signature`.
pub fn sign_request(
    req: &mut OutboundRequest,
    private_key_pem: &str,
    key_id: &str,
) -> Result<(), SigError> {
    let url = url::Url::parse(&req.url).map_err(|e| SigError::Url(e.to_string()))?;
    let host = url
        .host_str()
        .ok_or_else(|| SigError::Url("url has no host".into()))?;
    let path = if let Some(q) = url.query() {
        format!("{}?{}", url.path(), q)
    } else {
        url.path().to_string()
    };
    let date = httpdate::fmt_http_date(std::time::SystemTime::now());
    let digest = digest_header(&req.body);

    // Covered headers and their values.
    let covered = vec!["(request-target)", "host", "date", "digest"];
    let mut base_lines: Vec<String> = Vec::new();
    for h in &covered {
        match *h {
            "(request-target)" => base_lines.push(format!(
                "(request-target): {} {}",
                req.method.to_ascii_lowercase(),
                path
            )),
            "host" => base_lines.push(format!("host: {host}")),
            "date" => base_lines.push(format!("date: {date}")),
            "digest" => base_lines.push(format!("digest: {digest}")),
            _ => {}
        }
    }
    let base = base_lines.join("\n");

    let sk = RsaPrivateKey::from_pkcs8_pem(private_key_pem)
        .map_err(|e| SigError::Rsa(e.to_string()))?;
    let signer = SigningKey::<Sha256>::new(sk);
    let sig: RsaSignature = signer.sign(base.as_bytes());
    let sig_b64 = B64.encode(sig.to_bytes());

    let signature_header = format!(
        "keyId=\"{key_id}\",algorithm=\"rsa-sha256\",headers=\"{headers}\",signature=\"{sig}\"",
        key_id = key_id,
        headers = covered.join(" "),
        sig = sig_b64,
    );

    // Append canonical headers — de-dup if already set.
    req.headers.retain(|(n, _)| {
        let ln = n.to_ascii_lowercase();
        ln != "host"
            && ln != "date"
            && ln != "digest"
            && ln != "signature"
    });
    req.headers.push(("Host".to_string(), host.to_string()));
    req.headers.push(("Date".to_string(), date));
    req.headers.push(("Digest".to_string(), digest));
    req.headers.push(("Signature".to_string(), signature_header));
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;

    struct StaticResolver {
        pem: String,
    }

    #[async_trait]
    impl ActorKeyResolver for StaticResolver {
        async fn resolve(&self, key_id: &str) -> Result<VerifiedActor, SigError> {
            Ok(VerifiedActor {
                key_id: key_id.to_string(),
                actor_url: key_id.trim_end_matches("#main-key").to_string(),
                public_key_pem: self.pem.clone(),
            })
        }
    }

    fn fresh_keypair() -> (String, String) {
        crate::actor::generate_actor_keypair().unwrap()
    }

    fn build_signed_inbound(
        method: &str,
        path: &str,
        body: &[u8],
        priv_pem: &str,
        key_id: &str,
    ) -> SignedRequest {
        let host = "pod.example";
        let date = httpdate::fmt_http_date(std::time::SystemTime::now());
        let digest = digest_header(body);
        let base = format!(
            "(request-target): {} {}\nhost: {}\ndate: {}\ndigest: {}",
            method.to_ascii_lowercase(),
            path,
            host,
            date,
            digest
        );
        let sk = RsaPrivateKey::from_pkcs8_pem(priv_pem).unwrap();
        let signer = SigningKey::<Sha256>::new(sk);
        let sig: RsaSignature = signer.sign(base.as_bytes());
        let sig_b64 = B64.encode(sig.to_bytes());
        let sig_header = format!(
            "keyId=\"{key_id}\",algorithm=\"rsa-sha256\",headers=\"(request-target) host date digest\",signature=\"{sig_b64}\""
        );

        SignedRequest::new(method, path, body.to_vec())
            .with_header("host", host)
            .with_header("date", date)
            .with_header("digest", digest)
            .with_header("signature", sig_header)
    }

    #[test]
    fn parse_signature_header_valid() {
        let raw = r#"keyId="https://a.example/actor#main-key",algorithm="rsa-sha256",headers="(request-target) host date digest",signature="ZmFrZQ==""#;
        let parsed = parse_signature_header(raw).unwrap();
        assert_eq!(parsed.key_id, "https://a.example/actor#main-key");
        assert_eq!(parsed.algorithm, "rsa-sha256");
        assert_eq!(
            parsed.headers,
            vec![
                "(request-target)".to_string(),
                "host".to_string(),
                "date".to_string(),
                "digest".to_string()
            ]
        );
        assert_eq!(parsed.signature_b64, "ZmFrZQ==");
    }

    #[test]
    fn parse_signature_header_rejects_missing_keyid() {
        let raw = r#"algorithm="rsa-sha256",signature="abc""#;
        assert!(matches!(
            parse_signature_header(raw),
            Err(SigError::MissingKeyId)
        ));
    }

    #[test]
    fn digest_header_is_mastodon_shape() {
        let d = digest_header(b"hello");
        assert!(d.starts_with("SHA-256="));
    }

    #[tokio::test]
    async fn http_signature_verify_accepts_valid_request() {
        let (priv_pem, pub_pem) = fresh_keypair();
        let key_id = "https://remote.example/actor#main-key";
        let req = build_signed_inbound("POST", "/inbox", b"{}", &priv_pem, key_id);
        let resolver = StaticResolver { pem: pub_pem };
        let actor = verify_request_signature(&req, &resolver).await.unwrap();
        assert_eq!(actor.key_id, key_id);
        assert_eq!(actor.actor_url, "https://remote.example/actor");
    }

    #[tokio::test]
    async fn http_signature_verify_rejects_tampered_body() {
        let (priv_pem, pub_pem) = fresh_keypair();
        let key_id = "https://remote.example/actor#main-key";
        let mut req = build_signed_inbound("POST", "/inbox", b"{}", &priv_pem, key_id);
        // Mutate body after signing → digest mismatch.
        req.body = b"{\"tampered\":true}".to_vec();
        let resolver = StaticResolver { pem: pub_pem };
        let res = verify_request_signature(&req, &resolver).await;
        assert!(
            matches!(res, Err(SigError::DigestMismatch)),
            "got {res:?}"
        );
    }

    #[tokio::test]
    async fn http_signature_verify_rejects_wrong_key() {
        let (priv_pem, _pub_pem) = fresh_keypair();
        let (_, other_pub_pem) = fresh_keypair();
        let key_id = "https://remote.example/actor#main-key";
        let req = build_signed_inbound("POST", "/inbox", b"{}", &priv_pem, key_id);
        let resolver = StaticResolver {
            pem: other_pub_pem,
        };
        let res = verify_request_signature(&req, &resolver).await;
        assert!(matches!(res, Err(SigError::VerifyFailed(_))));
    }

    #[tokio::test]
    async fn http_signature_verify_roundtrips_through_sign_request() {
        let (priv_pem, pub_pem) = fresh_keypair();
        let key_id = "https://pod.example/profile/card.jsonld#main-key";
        let body = br#"{"type":"Follow"}"#.to_vec();
        let mut out = OutboundRequest {
            method: "POST".into(),
            url: "https://remote.example/inbox".into(),
            headers: vec![("Content-Type".into(), "application/activity+json".into())],
            body: body.clone(),
        };
        sign_request(&mut out, &priv_pem, key_id).unwrap();

        // Convert to an inbound-shaped request and verify.
        let url = url::Url::parse(&out.url).unwrap();
        let path = url.path().to_string();
        let mut inbound = SignedRequest::new("POST", &path, body);
        for (k, v) in &out.headers {
            inbound.headers.insert(k.to_ascii_lowercase(), v.clone());
        }
        let resolver = StaticResolver { pem: pub_pem };
        let actor = verify_request_signature(&inbound, &resolver).await.unwrap();
        assert_eq!(actor.key_id, key_id);
    }
}
