//! MCP tool definitions, dispatch, and the streaming `subscribe` upgrade.
//!
//! Each tool maps `(args, state, ctx) -> MCPToolResult`. Every WAC check
//! delegates to [`wac_check`], which reuses the pod's effective-ACL walk and
//! the same WAC 2.0 condition registry as the HTTP write path, so MCP tools
//! have identical access semantics to the REST endpoints.
//!
//! Mirrors JSS `src/mcp/tools.js`.

use std::time::Duration;

use actix_web::HttpResponse;
use bytes::Bytes;
use futures_util::stream::{self, StreamExt};
use serde_json::{json, Value};
use solid_pod_rs::include_dir::Dir;

use super::skills;
use super::{tool_error, tool_json, tool_text, McpCtx};
use crate::AppState;
use solid_pod_rs::ldp;
use solid_pod_rs::storage::StorageEvent;
use solid_pod_rs::wac::{
    self, conditions::RequestContext, document::IdOrIds, parse_jsonld_acl, AccessMode,
};

const ACL_NS: &str = "http://www.w3.org/ns/auth/acl#";
const FOAF_AGENT: &str = "http://xmlns.com/foaf/0.1/Agent";
const ACL_AUTH_AGENT: &str = "http://www.w3.org/ns/auth/acl#AuthenticatedAgent";
const MAX_READ_BYTES: usize = 200_000;
const MAX_FEDERATION_DEPTH: u32 = 3;

/// Safe allowlist of header names the `call_remote_pod` `header` auth mode may
/// forward to a remote pod. Deliberately narrow: only credential-carrying
/// headers, never hop/routing/identity headers (`Host`, `Cookie`,
/// `X-Forwarded-*`, `MCP-Federation-Depth`, …). Matched case-insensitively.
const FORWARDABLE_AUTH_HEADERS: &[&str] = &[
    "authorization",
    "x-api-key",
    "x-pod-admin-key",
    "x-auth-token",
];

/// Case-insensitive membership test for [`FORWARDABLE_AUTH_HEADERS`].
fn is_forwardable_auth_header(name: &str) -> bool {
    FORWARDABLE_AUTH_HEADERS
        .iter()
        .any(|h| name.eq_ignore_ascii_case(h))
}

/// Built-in docs tree, embedded at compile time so `list_docs` / `read_docs`
/// work from a self-contained binary (JSS ships a `docs/` directory). The
/// embedding lives in the owning crate (`solid_pod_rs::DOCS_DIR`, feature
/// `embedded-docs`) so registry builds of this crate stay self-contained.
use solid_pod_rs::DOCS_DIR;

// ---------------------------------------------------------------------------
// WAC + path helpers
// ---------------------------------------------------------------------------

fn build_url(ctx: &McpCtx, path: &str) -> String {
    if path.starts_with('/') {
        format!("{}{}", ctx.origin, path)
    } else {
        format!("{}/{}", ctx.origin, path)
    }
}

fn parent_path(p: &str) -> String {
    if p == "/" || p.is_empty() {
        return "/".to_string();
    }
    let trimmed = p.strip_suffix('/').unwrap_or(p);
    match trimmed.rfind('/') {
        Some(0) | None => "/".to_string(),
        Some(idx) => trimmed[..=idx].to_string(),
    }
}

/// WAC check mirroring the HTTP write path: for writes against a
/// non-existent resource, fall back to the parent container (same pattern
/// as `enforce_write`), so MCP tools and REST endpoints agree.
async fn wac_check(state: &AppState, ctx: &McpCtx, path: &str, mode: AccessMode) -> bool {
    let is_write = matches!(mode, AccessMode::Write | AccessMode::Append);
    let check_path =
        if is_write && !path.ends_with('/') && !state.storage.exists(path).await.unwrap_or(false) {
            parent_path(path)
        } else {
            path.to_string()
        };

    let acl_doc = match crate::find_effective_acl_dyn(&*state.storage, &check_path).await {
        Ok(doc) => doc,
        Err(_) => return false,
    };
    let payment_balance_sats =
        crate::resolve_balance_sats(&*state.storage, ctx.web_id.as_deref()).await;
    let rc = RequestContext {
        web_id: ctx.web_id.as_deref(),
        client_id: None,
        issuer: None,
        payment_balance_sats,
    };
    let registry = wac::conditions::ConditionRegistry::default_with_client_and_issuer();
    let groups = wac::StaticGroupMembership::default();
    // F4 `acl:origin`: thread the `/mcp` request Origin so an ACL that
    // restricts origins gates cross-origin tool calls.
    let request_origin = ctx.request_origin.as_deref().and_then(wac::Origin::parse);
    wac::evaluate_access_ctx_with_registry(
        acl_doc.as_ref(),
        &rc,
        &check_path,
        mode,
        request_origin.as_ref(),
        &groups,
        &registry,
    )
}

fn ids_of(val: &Option<IdOrIds>) -> Vec<String> {
    match val {
        None => Vec::new(),
        Some(IdOrIds::Single(r)) => vec![r.id.clone()],
        Some(IdOrIds::Multiple(v)) => v.iter().map(|r| r.id.clone()).collect(),
    }
}

// ---------------------------------------------------------------------------
// CRUD tools
// ---------------------------------------------------------------------------

async fn list_resources(args: &Value, state: &AppState, ctx: &McpCtx) -> Value {
    let path = args.get("path").and_then(Value::as_str).unwrap_or("");
    if path.is_empty() || !path.ends_with('/') {
        return tool_error("path must be a container (ending in /)");
    }
    if !wac_check(state, ctx, path, AccessMode::Read).await {
        return tool_error(format!("access denied: read {path}"));
    }
    if !state.storage.exists(path).await.unwrap_or(false) {
        return tool_error(format!("not found: {path}"));
    }
    let entries = match state.storage.list(path).await {
        Ok(e) => e,
        Err(e) => return tool_error(format!("list failed: {e}")),
    };
    let mut items: Vec<Value> = Vec::new();
    for entry in entries {
        let is_container = entry.ends_with('/');
        let name = entry.trim_end_matches('/').to_string();
        let child = format!("{path}{entry}");
        let meta = state.storage.head(&child).await.ok();
        items.push(json!({
            "name": name,
            "path": child,
            "isContainer": is_container,
            "size": meta.as_ref().map(|m| m.size).map(Value::from).unwrap_or(Value::Null),
            "modified": meta.as_ref().map(|m| m.modified.to_rfc3339()).map(Value::from).unwrap_or(Value::Null),
        }));
    }
    tool_json(json!({ "container": path, "items": items }))
}

async fn read_resource(args: &Value, state: &AppState, ctx: &McpCtx) -> Value {
    let path = args.get("path").and_then(Value::as_str).unwrap_or("");
    if path.is_empty() {
        return tool_error("path required");
    }
    if !wac_check(state, ctx, path, AccessMode::Read).await {
        return tool_error(format!("access denied: read {path}"));
    }
    if path.ends_with('/') {
        return tool_error("use list_resources for containers");
    }
    let (body, _meta) = match state.storage.get(path).await {
        Ok(v) => v,
        Err(_) => return tool_error(format!("not found: {path}")),
    };
    let full = String::from_utf8_lossy(&body);
    let truncated = full.len() > MAX_READ_BYTES;
    let body_str: String = if truncated {
        full.chars().take(MAX_READ_BYTES).collect()
    } else {
        full.into_owned()
    };
    let mut result = json!({ "path": path, "body": body_str });
    if truncated {
        result["truncated"] = json!(true);
    }
    tool_json(result)
}

async fn write_resource(args: &Value, state: &AppState, ctx: &McpCtx) -> Value {
    let path = args.get("path").and_then(Value::as_str).unwrap_or("");
    if path.is_empty() {
        return tool_error("path required");
    }
    if path.ends_with('/') {
        return tool_error("cannot PUT a container; use create_resource");
    }
    let content = match args.get("content").and_then(Value::as_str) {
        Some(c) => c,
        None => return tool_error("content required"),
    };
    let content_type = args
        .get("contentType")
        .and_then(Value::as_str)
        .unwrap_or("text/plain");
    if !wac_check(state, ctx, path, AccessMode::Write).await {
        return tool_error(format!("access denied: write {path}"));
    }
    let bytes = Bytes::from(content.as_bytes().to_vec());
    let len = bytes.len();
    match state.storage.put(path, bytes, content_type).await {
        Ok(_) => tool_text(format!("wrote {path} ({len} bytes)")),
        Err(e) => tool_error(format!("write failed: {e}")),
    }
}

async fn create_resource(args: &Value, state: &AppState, ctx: &McpCtx) -> Value {
    let container = args.get("container").and_then(Value::as_str).unwrap_or("");
    if container.is_empty() || !container.ends_with('/') {
        return tool_error("container path required (must end in /)");
    }
    if !wac_check(state, ctx, container, AccessMode::Append).await {
        return tool_error(format!("access denied: append {container}"));
    }
    if !state.storage.exists(container).await.unwrap_or(false) {
        return tool_error(format!("container not found: {container}"));
    }
    let slug = args.get("slug").and_then(Value::as_str);
    let is_container = args
        .get("isContainer")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let base = match ldp::resolve_slug(container, slug) {
        Ok(p) => p,
        Err(e) => return tool_error(format!("invalid slug: {e}")),
    };
    if is_container {
        let child = format!("{base}/");
        match state.storage.create_container(&child).await {
            Ok(_) => tool_text(format!("created container {child}")),
            Err(e) => tool_error(format!("create failed: {e}")),
        }
    } else {
        let content = args.get("content").and_then(Value::as_str).unwrap_or("");
        let content_type = args
            .get("contentType")
            .and_then(Value::as_str)
            .unwrap_or("text/plain");
        let bytes = Bytes::from(content.as_bytes().to_vec());
        match state.storage.put(&base, bytes, content_type).await {
            Ok(_) => tool_text(format!("created {base}")),
            Err(e) => tool_error(format!("create failed: {e}")),
        }
    }
}

async fn delete_resource(args: &Value, state: &AppState, ctx: &McpCtx) -> Value {
    let path = args.get("path").and_then(Value::as_str).unwrap_or("");
    if path.is_empty() {
        return tool_error("path required");
    }
    if !wac_check(state, ctx, path, AccessMode::Write).await {
        return tool_error(format!("access denied: delete {path}"));
    }
    if !state.storage.exists(path).await.unwrap_or(false) {
        return tool_error(format!("not found: {path}"));
    }
    match state.storage.delete(path).await {
        Ok(()) => tool_text(format!("deleted {path}")),
        Err(e) => tool_error(format!("delete failed: {e}")),
    }
}

async fn head_resource(args: &Value, state: &AppState, ctx: &McpCtx) -> Value {
    let path = args.get("path").and_then(Value::as_str).unwrap_or("");
    if path.is_empty() {
        return tool_error("path required");
    }
    if !wac_check(state, ctx, path, AccessMode::Read).await {
        return tool_error(format!("access denied: read {path}"));
    }
    let meta = match state.storage.head(path).await {
        Ok(m) => m,
        Err(_) => return tool_error(format!("not found: {path}")),
    };
    tool_json(json!({
        "path": path,
        "isContainer": path.ends_with('/'),
        "size": meta.size,
        "modified": meta.modified.to_rfc3339(),
    }))
}

// ---------------------------------------------------------------------------
// Skill tools
// ---------------------------------------------------------------------------

async fn list_skills(_args: &Value, state: &AppState, _ctx: &McpCtx) -> Value {
    tool_json(skills::discover_skills(&*state.storage).await)
}

async fn get_skill(args: &Value, state: &AppState, _ctx: &McpCtx) -> Value {
    let path = args.get("path").and_then(Value::as_str).unwrap_or("");
    if path.is_empty() {
        return tool_error("path required");
    }
    match skills::read_skill(&*state.storage, path).await {
        Ok(v) => tool_json(v),
        Err(e) => tool_error(e),
    }
}

async fn get_pod_skill(_args: &Value, state: &AppState, _ctx: &McpCtx) -> Value {
    match skills::read_pod_skill(&*state.storage).await {
        Some(v) => tool_json(v),
        None => tool_text("no pod-wide SKILL.md or SKILL.jsonld"),
    }
}

// ---------------------------------------------------------------------------
// Docs tools (built-in, compile-time embedded)
// ---------------------------------------------------------------------------

fn collect_docs(dir: &Dir<'_>, out: &mut Vec<Value>) {
    for file in dir.files() {
        let path = file.path();
        if path.extension().and_then(|e| e.to_str()) == Some("md") {
            out.push(json!({
                "name": path.to_string_lossy(),
                "size": file.contents().len(),
            }));
        }
    }
    for sub in dir.dirs() {
        collect_docs(sub, out);
    }
}

async fn list_docs(_args: &Value, _state: &AppState, _ctx: &McpCtx) -> Value {
    let mut docs: Vec<Value> = Vec::new();
    collect_docs(&DOCS_DIR, &mut docs);
    tool_json(json!({ "source": "jss-builtin", "docs": docs }))
}

async fn read_docs(args: &Value, _state: &AppState, _ctx: &McpCtx) -> Value {
    let mut name = match args.get("name").and_then(Value::as_str) {
        Some(n) if !n.is_empty() => n.to_string(),
        _ => return tool_error("name required (e.g. \"reference/cli.md\")"),
    };
    // The embedded tree is nested, so '/' is permitted in names; '..' and a
    // leading '/' are not (no traversal outside the bundle).
    if name.contains("..") || name.starts_with('/') {
        return tool_error("name must be a relative path with no '..' segments");
    }
    if !name.ends_with(".md") {
        name.push_str(".md");
    }
    match DOCS_DIR.get_file(&name) {
        Some(file) => {
            let body = String::from_utf8_lossy(file.contents()).into_owned();
            tool_json(json!({ "name": name, "body": body }))
        }
        None => tool_error(format!("doc not found: {name}")),
    }
}

// ---------------------------------------------------------------------------
// Pod info
// ---------------------------------------------------------------------------

async fn pod_info(_args: &Value, state: &AppState, ctx: &McpCtx) -> Value {
    let skill = skills::read_pod_skill(&*state.storage).await;
    tool_json(json!({
        "pod": ctx.origin,
        "server": "solid-pod-rs",
        "protocolVersion": super::PROTOCOL_VERSION,
        "identity": ctx.web_id.clone().map(Value::from).unwrap_or(Value::Null),
        "capabilities": { "crud": true, "acl": true, "skills": true, "docs": true },
        "skill": skill.map(|s| json!({
            "path": s.get("path").cloned().unwrap_or(Value::Null),
            "format": s.get("format").cloned().unwrap_or(Value::Null),
        })).unwrap_or(Value::Null),
    }))
}

// ---------------------------------------------------------------------------
// ACL tools (#496)
// ---------------------------------------------------------------------------

fn acl_url_for(path: &str) -> String {
    format!("{path}.acl")
}

fn short_mode(mode: &str) -> String {
    mode.rsplit(['#', ':']).next().unwrap_or(mode).to_string()
}

fn short_agent_class(uri: &str) -> String {
    match uri {
        FOAF_AGENT | "foaf:Agent" => "foaf:Agent".to_string(),
        ACL_AUTH_AGENT | "acl:AuthenticatedAgent" => "acl:AuthenticatedAgent".to_string(),
        other => other.to_string(),
    }
}

fn full_agent_class(value: &str) -> String {
    match value {
        "foaf:Agent" => FOAF_AGENT.to_string(),
        "acl:AuthenticatedAgent" => ACL_AUTH_AGENT.to_string(),
        other => other.to_string(),
    }
}

async fn read_acl(args: &Value, state: &AppState, ctx: &McpCtx) -> Value {
    let path = args.get("path").and_then(Value::as_str).unwrap_or("");
    if path.is_empty() {
        return tool_error("path required");
    }
    if !wac_check(state, ctx, path, AccessMode::Control).await {
        return tool_error(format!("access denied: control {path}"));
    }
    let acl_path = acl_url_for(path);
    let (body, _meta) = match state.storage.get(&acl_path).await {
        Ok(v) => v,
        Err(_) => {
            return tool_json(json!({
                "path": path, "aclPath": acl_path, "exists": false, "authorizations": []
            }))
        }
    };
    let doc = match parse_jsonld_acl(&body) {
        Ok(d) => d,
        Err(_) => match solid_pod_rs::wac::parse_turtle_acl(&String::from_utf8_lossy(&body)) {
            Ok(d) => d,
            Err(e) => return tool_error(format!("acl parse failed: {e}")),
        },
    };
    let auths: Vec<Value> = doc
        .graph
        .unwrap_or_default()
        .iter()
        .map(|a| {
            json!({
                "agents": ids_of(&a.agent),
                "agentClasses": ids_of(&a.agent_class).iter().map(|c| short_agent_class(c)).collect::<Vec<_>>(),
                "modes": ids_of(&a.mode).iter().map(|m| short_mode(m)).collect::<Vec<_>>(),
                "isDefault": a.default.is_some(),
            })
        })
        .collect();
    tool_json(json!({
        "path": path, "aclPath": acl_path, "exists": true, "authorizations": auths
    }))
}

/// Build a JSON-LD ACL document from a structured authorizations array.
/// `accessTo` (and `default`, when requested) are set to the absolute pod
/// `path` so the WAC evaluator matches them, mirroring JSS `buildAclDoc`.
fn build_acl_jsonld(path: &str, authorizations: &[Value]) -> Value {
    let graph: Vec<Value> = authorizations
        .iter()
        .enumerate()
        .map(|(i, auth)| {
            let modes: Vec<Value> = auth
                .get("modes")
                .and_then(Value::as_array)
                .map(|ms| {
                    ms.iter()
                        .filter_map(Value::as_str)
                        .map(|m| json!({ "@id": format!("acl:{m}") }))
                        .collect()
                })
                .unwrap_or_default();
            let mut node = json!({
                "@id": format!("#auth{i}"),
                "@type": "acl:Authorization",
                "acl:accessTo": { "@id": path },
                "acl:mode": modes,
            });
            if let Some(agents) = auth.get("agents").and_then(Value::as_array) {
                if !agents.is_empty() {
                    node["acl:agent"] = Value::Array(
                        agents
                            .iter()
                            .filter_map(Value::as_str)
                            .map(|a| json!({ "@id": a }))
                            .collect(),
                    );
                }
            }
            if let Some(classes) = auth.get("agentClasses").and_then(Value::as_array) {
                if !classes.is_empty() {
                    node["acl:agentClass"] = Value::Array(
                        classes
                            .iter()
                            .filter_map(Value::as_str)
                            .map(|c| json!({ "@id": full_agent_class(c) }))
                            .collect(),
                    );
                }
            }
            if auth
                .get("isDefault")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                node["acl:default"] = json!({ "@id": path });
            }
            node
        })
        .collect();
    json!({
        "@context": { "acl": ACL_NS, "foaf": "http://xmlns.com/foaf/0.1/" },
        "@graph": graph,
    })
}

async fn write_acl(args: &Value, state: &AppState, ctx: &McpCtx) -> Value {
    let path = args.get("path").and_then(Value::as_str).unwrap_or("");
    if path.is_empty() {
        return tool_error("path required");
    }
    let authorizations = match args.get("authorizations").and_then(Value::as_array) {
        Some(a) => a,
        None => return tool_error("authorizations must be an array"),
    };
    if !wac_check(state, ctx, path, AccessMode::Control).await {
        return tool_error(format!("access denied: control {path}"));
    }
    let doc = build_acl_jsonld(path, authorizations);
    let serialized = serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".to_string());

    // Lockout guard: refuse an ACL that would not grant Control to the
    // caller — the most common write_acl footgun. Parse the proposed
    // document back and confirm at least one authorization grants Control
    // to this principal (by WebID or agent class).
    let proposed = match parse_jsonld_acl(serialized.as_bytes()) {
        Ok(d) => d,
        Err(e) => return tool_error(format!("internal: proposed ACL did not parse: {e}")),
    };
    let caller_has_control = proposed
        .graph
        .as_deref()
        .unwrap_or_default()
        .iter()
        .any(|a| {
            let grants_control = ids_of(&a.mode)
                .iter()
                .any(|m| short_mode(m).eq_ignore_ascii_case("Control"));
            if !grants_control {
                return false;
            }
            let agents = ids_of(&a.agent);
            if let Some(web_id) = ctx.web_id.as_deref() {
                if agents.iter().any(|x| x == web_id) {
                    return true;
                }
            }
            let classes = ids_of(&a.agent_class);
            if classes.iter().any(|c| c == FOAF_AGENT || c == "foaf:Agent") {
                return true;
            }
            if ctx.web_id.is_some()
                && classes
                    .iter()
                    .any(|c| c == ACL_AUTH_AGENT || c == "acl:AuthenticatedAgent")
            {
                return true;
            }
            false
        });
    if !caller_has_control {
        return tool_error(format!(
            "write_acl refused: the proposed ACL would not grant Control to the caller ({}). \
             Use an absolute WebID in `agents`. To transfer ownership, grant Control to the new \
             owner first, then have them rewrite the ACL without you.",
            ctx.web_id.as_deref().unwrap_or("anonymous")
        ));
    }

    let acl_path = acl_url_for(path);
    let bytes = Bytes::from(serialized.into_bytes());
    match state
        .storage
        .put(&acl_path, bytes, "application/ld+json")
        .await
    {
        Ok(_) => tool_text(format!(
            "wrote {acl_path} ({} authorization{})",
            authorizations.len(),
            if authorizations.len() == 1 { "" } else { "s" }
        )),
        Err(e) => tool_error(format!("write failed: {e}")),
    }
}

// ---------------------------------------------------------------------------
// Federation (#495)
// ---------------------------------------------------------------------------

/// Federation gate path for a local WebID. Single-user `did:nostr` pods
/// gate outbound federation on `/private/federation/`; foreign or anonymous
/// identities cannot initiate it (no local path to authorise against).
fn federation_gate_path(web_id: Option<&str>) -> Option<String> {
    let did = web_id?;
    if !did.starts_with("did:nostr:") {
        return None;
    }
    Some("/private/federation/".to_string())
}

async fn call_remote_pod(args: &Value, state: &AppState, ctx: &McpCtx) -> Value {
    let pod_url = match args.get("pod_url").and_then(Value::as_str) {
        Some(u) if !u.is_empty() => u,
        _ => return tool_error("pod_url required"),
    };
    let tool = match args.get("tool").and_then(Value::as_str) {
        Some(t) if !t.is_empty() => t,
        _ => return tool_error("tool required"),
    };
    // Parse + SSRF-validate the target. A bare `Url::parse` (the previous
    // check) accepts `http://127.0.0.1`, `http://169.254.169.254` (cloud
    // metadata), and hostnames that resolve into private space — a federation
    // SSRF. Enforce an http(s) scheme, the literal-host blocklist, and a
    // DNS-resolving check whose resolved IP is pinned on the outbound client
    // (below) so the socket cannot be rebound to an internal address.
    let parsed_pod_url = match url::Url::parse(pod_url) {
        Ok(u) => u,
        Err(_) => return tool_error(format!("pod_url is not a valid URL: {pod_url}")),
    };
    match parsed_pod_url.scheme() {
        "http" | "https" => {}
        scheme => {
            return tool_error(format!(
                "pod_url scheme not allowed: {scheme} (use http/https)"
            ))
        }
    }
    if solid_pod_rs::security::is_safe_url(pod_url).is_err() {
        return tool_error("pod_url blocked by SSRF policy");
    }
    let pod_host = match parsed_pod_url.host_str() {
        Some(h) => h.to_string(),
        None => return tool_error("pod_url has no host"),
    };
    let pinned_ip = match solid_pod_rs::security::resolve_and_check(&pod_host).await {
        Ok(ip) => ip,
        Err(_) => return tool_error("pod_url blocked by SSRF policy"),
    };

    let gate = match federation_gate_path(ctx.web_id.as_deref()) {
        Some(g) => g,
        None => {
            return tool_error(
                "access denied: federation requires a local did:nostr WebID identity \
                 (anonymous and foreign identities cannot initiate outbound federation)",
            )
        }
    };
    if !wac_check(state, ctx, &gate, AccessMode::Write).await {
        return tool_error(format!(
            "access denied: write {gate} (federation gate). Owner must grant acl:Write at this \
             path to delegate outbound federation."
        ));
    }

    let depth = ctx.federation_depth + 1;
    if depth > MAX_FEDERATION_DEPTH {
        return tool_error(format!(
            "federation depth exceeded (max {MAX_FEDERATION_DEPTH})"
        ));
    }

    let remote_endpoint = format!("{}/mcp", pod_url.trim_end_matches('/'));
    let remote_args = args.get("arguments").cloned().unwrap_or_else(|| json!({}));
    let rpc_body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": { "name": tool, "arguments": remote_args }
    });

    // Pin DNS to the vetted IP and disable redirect-following so the request
    // can't be bounced to an internal target after the SSRF check (port 0 ⇒
    // reqwest keeps the URL's port).
    let client = match reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .resolve(
            &pod_host,
            std::net::SocketAddr::new(
                pinned_ip,
                parsed_pod_url.port_or_known_default().unwrap_or(0),
            ),
        )
        .build()
    {
        Ok(c) => c,
        Err(e) => return tool_error(format!("federation client build failed: {e}")),
    };
    let mut request = client
        .post(&remote_endpoint)
        .timeout(Duration::from_secs(30))
        .header("Content-Type", "application/json")
        .header("MCP-Federation-Depth", depth.to_string());
    if let Some(auth) = args.get("auth").and_then(Value::as_object) {
        match auth.get("type").and_then(Value::as_str) {
            Some("bearer") => {
                if let Some(token) = auth.get("token").and_then(Value::as_str) {
                    request = request.header("Authorization", format!("Bearer {token}"));
                }
            }
            Some("header") => {
                if let (Some(name), Some(value)) = (
                    auth.get("name").and_then(Value::as_str),
                    auth.get("value").and_then(Value::as_str),
                ) {
                    // Only forward a conservative allowlist of auth header
                    // names — never arbitrary attacker-chosen headers (which
                    // could smuggle Host/Cookie/X-Forwarded-* or other
                    // sensitive fields to the remote pod).
                    if is_forwardable_auth_header(name) {
                        request = request.header(name, value);
                    } else {
                        return tool_error(format!(
                            "auth header '{name}' is not forwardable (allowed: {})",
                            FORWARDABLE_AUTH_HEADERS.join(", ")
                        ));
                    }
                }
            }
            _ => {}
        }
    }

    let response = match request.json(&rpc_body).send().await {
        Ok(r) => r,
        Err(e) => return tool_error(format!("remote pod unreachable: {e}")),
    };
    let status = response.status();
    let payload: Value = match response.json().await {
        Ok(v) => v,
        Err(e) => return tool_error(format!("remote response not JSON ({status}): {e}")),
    };
    if let Some(err) = payload.get("error") {
        let code = err.get("code").and_then(Value::as_i64).unwrap_or(0);
        let msg = err.get("message").and_then(Value::as_str).unwrap_or("");
        return tool_error(format!("remote MCP error {code}: {msg}"));
    }
    tool_json(json!({
        "pod_url": pod_url,
        "tool": tool,
        "depth": depth,
        "remote_result": payload.get("result").cloned().unwrap_or(Value::Null),
    }))
}

// ---------------------------------------------------------------------------
// Dispatch + registry
// ---------------------------------------------------------------------------

/// Invoke a tool by name. Unknown tools and the streaming `subscribe`
/// (handled out-of-band by [`handle_subscribe`]) return an error envelope.
pub async fn call_tool(name: &str, args: &Value, state: &AppState, ctx: &McpCtx) -> Value {
    match name {
        "list_resources" => list_resources(args, state, ctx).await,
        "read_resource" => read_resource(args, state, ctx).await,
        "write_resource" => write_resource(args, state, ctx).await,
        "create_resource" => create_resource(args, state, ctx).await,
        "delete_resource" => delete_resource(args, state, ctx).await,
        "head_resource" => head_resource(args, state, ctx).await,
        "list_skills" => list_skills(args, state, ctx).await,
        "get_skill" => get_skill(args, state, ctx).await,
        "get_pod_skill" => get_pod_skill(args, state, ctx).await,
        "list_docs" => list_docs(args, state, ctx).await,
        "read_docs" => read_docs(args, state, ctx).await,
        "pod_info" => pod_info(args, state, ctx).await,
        "read_acl" => read_acl(args, state, ctx).await,
        "write_acl" => write_acl(args, state, ctx).await,
        "call_remote_pod" => call_remote_pod(args, state, ctx).await,
        "subscribe" => {
            tool_error("subscribe is a streaming tool; the server handles it over SSE directly")
        }
        other => tool_error(format!("unknown tool: {other}")),
    }
}

/// Tool metadata in MCP `tools/list` shape.
pub fn list_tools_for_rpc() -> Value {
    json!([
        { "name": "list_resources",
          "description": "List contents of an LDP container. Returns child resources and sub-containers.",
          "inputSchema": { "type": "object", "properties": { "path": { "type": "string", "description": "Container path, must end in /" } }, "required": ["path"] } },
        { "name": "read_resource",
          "description": "Read the body of a non-container resource (any content type). Returns UTF-8.",
          "inputSchema": { "type": "object", "properties": { "path": { "type": "string" } }, "required": ["path"] } },
        { "name": "write_resource",
          "description": "Write (PUT) a resource at the given path. Overwrites if exists.",
          "inputSchema": { "type": "object", "properties": { "path": { "type": "string" }, "content": { "type": "string" }, "contentType": { "type": "string", "description": "MIME type (default text/plain)" } }, "required": ["path", "content"] } },
        { "name": "create_resource",
          "description": "Create a child resource in a container (LDP POST). Server mints the name unless slug is provided.",
          "inputSchema": { "type": "object", "properties": { "container": { "type": "string", "description": "Parent container path, must end in /" }, "slug": { "type": "string", "description": "Optional filename hint" }, "content": { "type": "string" }, "contentType": { "type": "string" }, "isContainer": { "type": "boolean", "description": "Create a child container instead of a resource" } }, "required": ["container"] } },
        { "name": "delete_resource",
          "description": "Delete a resource or empty container.",
          "inputSchema": { "type": "object", "properties": { "path": { "type": "string" } }, "required": ["path"] } },
        { "name": "head_resource",
          "description": "Return metadata (size, modified) for a resource without reading the body.",
          "inputSchema": { "type": "object", "properties": { "path": { "type": "string" } }, "required": ["path"] } },
        { "name": "list_skills",
          "description": "List SKILL.md / SKILL.jsonld files at conventional paths (pod-wide, per-app, per-bot).",
          "inputSchema": { "type": "object", "properties": {} } },
        { "name": "get_skill",
          "description": "Read a specific skill file by pod path.",
          "inputSchema": { "type": "object", "properties": { "path": { "type": "string" } }, "required": ["path"] } },
        { "name": "get_pod_skill",
          "description": "Read the pod-wide SKILL.md (the owner's instructions to bots).",
          "inputSchema": { "type": "object", "properties": {} } },
        { "name": "list_docs",
          "description": "List the server's built-in docs (markdown shipped with the binary).",
          "inputSchema": { "type": "object", "properties": {} } },
        { "name": "read_docs",
          "description": "Read a built-in doc by relative path (e.g. \"reference/cli.md\").",
          "inputSchema": { "type": "object", "properties": { "name": { "type": "string" } }, "required": ["name"] } },
        { "name": "pod_info",
          "description": "Basic pod identity and MCP capabilities.",
          "inputSchema": { "type": "object", "properties": {} } },
        { "name": "read_acl",
          "description": "Read the WAC ACL for a resource as a structured list of authorizations. Requires acl:Control.",
          "inputSchema": { "type": "object", "properties": { "path": { "type": "string" } }, "required": ["path"] } },
        { "name": "write_acl",
          "description": "Write a structured ACL for a resource. authorizations: [{ agents?, agentClasses?, modes, isDefault? }]. Requires acl:Control.",
          "inputSchema": { "type": "object", "properties": { "path": { "type": "string" }, "authorizations": { "type": "array", "items": { "type": "object", "properties": { "agents": { "type": "array", "items": { "type": "string" } }, "agentClasses": { "type": "array", "items": { "type": "string", "enum": ["foaf:Agent", "acl:AuthenticatedAgent"] } }, "modes": { "type": "array", "items": { "type": "string", "enum": ["Read", "Write", "Append", "Control"] } }, "isDefault": { "type": "boolean" } }, "required": ["modes"] } } }, "required": ["path", "authorizations"] } },
        { "name": "subscribe",
          "description": "Subscribe to change events on a resource or container subtree. Returns an SSE stream of MCP notifications as resources change. WAC-filtered per event.",
          "inputSchema": { "type": "object", "properties": { "path": { "type": "string", "description": "Container path (with trailing /) to watch a subtree, or exact resource path. Default: / (whole pod, filtered by Read access)." } } } },
        { "name": "call_remote_pod",
          "description": "Invoke an MCP tool on another pod. Caller must have acl:Write on /private/federation/ on this pod. Depth-capped at 3.",
          "inputSchema": { "type": "object", "properties": { "pod_url": { "type": "string", "description": "Origin of the remote pod (e.g. https://alice.example.com)" }, "tool": { "type": "string", "description": "Tool name to invoke on the remote" }, "arguments": { "type": "object", "description": "Arguments to pass to the remote tool" }, "auth": { "type": "object", "description": "Auth for the remote call. { type: \"bearer\", token } or { type: \"header\", name, value }. Omit for anonymous.", "properties": { "type": { "type": "string", "enum": ["bearer", "header"] }, "token": { "type": "string" }, "name": { "type": "string" }, "value": { "type": "string" } } } }, "required": ["pod_url", "tool"] } }
    ])
}

// ---------------------------------------------------------------------------
// Streaming: subscribe (#494)
// ---------------------------------------------------------------------------

/// True when `msg` is a `tools/call` for the streaming `subscribe` tool.
pub fn is_streaming_call(msg: &Value) -> bool {
    msg.get("method").and_then(Value::as_str) == Some("tools/call")
        && msg
            .get("params")
            .and_then(|p| p.get("name"))
            .and_then(Value::as_str)
            == Some("subscribe")
}

fn path_matches_scope(event_path: &str, scope: &str) -> bool {
    if scope == "/" {
        return true;
    }
    if scope.ends_with('/') {
        event_path.starts_with(scope)
    } else {
        event_path == scope
    }
}

fn sse_event(payload: &Value) -> Bytes {
    let note = json!({
        "jsonrpc": "2.0",
        "method": "notifications/tool_event",
        "params": { "tool": "subscribe", "event": payload }
    });
    Bytes::from(format!("event: notification\ndata: {note}\n\n"))
}

/// Upgrade a `subscribe` call to an SSE stream driven by `storage.watch`.
/// Each change event is WAC-filtered against the subscriber's Read access
/// before emission, so the stream never leaks resources the caller can't
/// see. The stream stays open until the client disconnects.
pub async fn handle_subscribe(msg: &Value, state: AppState, ctx: McpCtx) -> HttpResponse {
    let scope = msg
        .get("params")
        .and_then(|p| p.get("arguments"))
        .and_then(|a| a.get("path"))
        .and_then(Value::as_str)
        .unwrap_or("/")
        .to_string();

    let receiver = match state.storage.watch(&scope).await {
        Ok(rx) => rx,
        Err(_) => {
            // Fall back to a single-shot JSON error if the backend can't watch.
            return HttpResponse::Ok().json(tool_error(format!(
                "subscribe failed: storage does not support watching {scope}"
            )));
        }
    };

    let initial = sse_event(&json!({
        "type": "subscribed",
        "scope": scope,
        "origin": ctx.origin,
        "identity": ctx.web_id.clone().map(Value::from).unwrap_or(Value::Null),
    }));

    let body_stream =
        stream::once(async move { Ok::<Bytes, std::io::Error>(initial) }).chain(stream::unfold(
            (receiver, state, ctx, scope),
            |(mut rx, state, ctx, scope)| async move {
                loop {
                    let event = rx.recv().await?;
                    let event_path = match &event {
                        StorageEvent::Created(p)
                        | StorageEvent::Updated(p)
                        | StorageEvent::Deleted(p) => p.clone(),
                    };
                    if !path_matches_scope(&event_path, &scope) {
                        continue;
                    }
                    if !wac_check(&state, &ctx, &event_path, AccessMode::Read).await {
                        continue;
                    }
                    let kind = match event {
                        StorageEvent::Created(_) => "created",
                        StorageEvent::Updated(_) => "updated",
                        StorageEvent::Deleted(_) => "deleted",
                    };
                    let chunk = sse_event(&json!({
                        "type": "resource_changed",
                        "change": kind,
                        "path": event_path,
                        "url": build_url(&ctx, &event_path),
                    }));
                    return Some((Ok(chunk), (rx, state, ctx, scope)));
                }
            },
        ));

    HttpResponse::Ok()
        .insert_header(("Content-Type", "text/event-stream"))
        .insert_header(("Cache-Control", "no-cache, no-transform"))
        .insert_header(("X-Accel-Buffering", "no"))
        .streaming(body_stream)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forwardable_auth_header_allowlist_is_case_insensitive() {
        assert!(is_forwardable_auth_header("Authorization"));
        assert!(is_forwardable_auth_header("authorization"));
        assert!(is_forwardable_auth_header("X-API-Key"));
        assert!(is_forwardable_auth_header("x-pod-admin-key"));
        assert!(is_forwardable_auth_header("X-Auth-Token"));
    }

    #[test]
    fn forwardable_auth_header_rejects_dangerous_names() {
        // Routing / identity / hop headers must never be forwardable.
        for bad in [
            "Host",
            "Cookie",
            "X-Forwarded-For",
            "X-Forwarded-Host",
            "MCP-Federation-Depth",
            "Content-Length",
            "",
        ] {
            assert!(
                !is_forwardable_auth_header(bad),
                "{bad} must not be forwardable"
            );
        }
    }
}
