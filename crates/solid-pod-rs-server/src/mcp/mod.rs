//! MCP (Model Context Protocol) server subsystem.
//!
//! Implements the Streamable HTTP transport for MCP 2025-03-26 over a
//! single `POST /mcp` endpoint. Clients send JSON-RPC 2.0 requests; the
//! server replies with JSON-RPC 2.0 responses (single-shot JSON, with an
//! SSE upgrade for the streaming `subscribe` tool).
//!
//! Mounted only when [`AppState::mcp_enabled`] is set (`--mcp` / `JSS_MCP`,
//! JSS #490). Identity reuses the pod's NIP-98 auth chain so MCP tool calls
//! get the same WAC treatment as any other request: an anonymous `/mcp`
//! request runs tools as the anonymous principal.
//!
//! Mirrors JSS `src/mcp/{index,protocol,tools,skills}.js`.
//!
//! Spec: <https://spec.modelcontextprotocol.io/specification/2025-03-26/>

mod skills;
mod tools;

use actix_web::{web, HttpRequest, HttpResponse};
use serde_json::{json, Value};

use crate::AppState;

pub const PROTOCOL_VERSION: &str = "2025-03-26";
const SERVER_NAME: &str = "jss-mcp";
const SERVER_VERSION: &str = "0.1.0";

// JSON-RPC error codes (subset; MCP-specific codes live in tools.rs scope).
const RPC_INVALID_REQUEST: i64 = -32600;
const RPC_METHOD_NOT_FOUND: i64 = -32601;
const RPC_INVALID_PARAMS: i64 = -32602;

/// Per-request MCP execution context. `web_id` is the authenticated
/// principal (`did:nostr:<pubkey>` for a NIP-98 caller; `None` =
/// anonymous). `origin` builds absolute URLs for WAC checks. `federation_depth`
/// enforces the `call_remote_pod` recursion cap.
#[derive(Clone)]
pub struct McpCtx {
    pub web_id: Option<String>,
    pub origin: String,
    pub federation_depth: u32,
}

// ---------------------------------------------------------------------------
// Protocol envelope helpers (mirror src/mcp/protocol.js)
// ---------------------------------------------------------------------------

fn rpc_result(id: &Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn rpc_error(id: &Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

/// MCP tool-result envelope carrying a single text block.
fn tool_text(text: impl Into<String>) -> Value {
    json!({ "content": [{ "type": "text", "text": text.into() }], "isError": false })
}

/// MCP tool-result envelope flagged as an error.
fn tool_error(message: impl Into<String>) -> Value {
    json!({ "content": [{ "type": "text", "text": message.into() }], "isError": true })
}

/// MCP tool-result envelope carrying pretty-printed JSON as text.
fn tool_json(value: Value) -> Value {
    tool_text(serde_json::to_string_pretty(&value).unwrap_or_else(|_| "null".to_string()))
}

// ---------------------------------------------------------------------------
// JSON-RPC dispatch
// ---------------------------------------------------------------------------

fn is_allowed_method(method: &str) -> bool {
    matches!(
        method,
        "initialize"
            | "initialized"
            | "notifications/initialized"
            | "tools/list"
            | "tools/call"
            | "ping"
    )
}

/// Dispatch a single JSON-RPC message. Returns `None` for notifications
/// (which carry no `id` and produce no response body).
async fn dispatch(msg: &Value, state: &AppState, ctx: &McpCtx) -> Option<Value> {
    let id = msg.get("id").cloned().unwrap_or(Value::Null);
    let method = msg.get("method").and_then(Value::as_str).unwrap_or("");

    if !is_allowed_method(method) {
        return Some(rpc_error(
            &id,
            RPC_METHOD_NOT_FOUND,
            &format!("unknown method: {method}"),
        ));
    }

    match method {
        "ping" => Some(rpc_result(&id, json!({}))),
        "initialize" => Some(rpc_result(
            &id,
            json!({
                "protocolVersion": PROTOCOL_VERSION,
                "serverInfo": { "name": SERVER_NAME, "version": SERVER_VERSION },
                "capabilities": { "tools": { "listChanged": false } }
            }),
        )),
        // Notifications carry no id; nothing to return.
        "initialized" | "notifications/initialized" => None,
        "tools/list" => Some(rpc_result(&id, json!({ "tools": tools::list_tools_for_rpc() }))),
        "tools/call" => {
            let name = msg
                .get("params")
                .and_then(|p| p.get("name"))
                .and_then(Value::as_str);
            let name = match name {
                Some(n) if !n.is_empty() => n,
                _ => return Some(rpc_error(&id, RPC_INVALID_PARAMS, "tool name required")),
            };
            let args = msg
                .get("params")
                .and_then(|p| p.get("arguments"))
                .cloned()
                .unwrap_or_else(|| json!({}));
            let result = tools::call_tool(name, &args, state, ctx).await;
            Some(rpc_result(&id, result))
        }
        _ => Some(rpc_error(
            &id,
            RPC_METHOD_NOT_FOUND,
            &format!("unhandled method: {method}"),
        )),
    }
}

// ---------------------------------------------------------------------------
// Actix handlers
// ---------------------------------------------------------------------------

fn origin_of(req: &HttpRequest) -> String {
    let conn = req.connection_info();
    format!("{}://{}", conn.scheme(), conn.host())
}

/// `POST /mcp` — JSON-RPC 2.0 over the MCP Streamable HTTP transport.
pub async fn handle_mcp(
    req: HttpRequest,
    body: web::Bytes,
    state: web::Data<AppState>,
) -> HttpResponse {
    let parsed: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => {
            return HttpResponse::BadRequest()
                .json(rpc_error(&Value::Null, RPC_INVALID_REQUEST, "expected JSON-RPC body"));
        }
    };

    // Identity for tool calls — pulled from the inbound auth on /mcp itself.
    // `None` web_id means "anonymous"; WAC treats it accordingly. Reuses the
    // pod's NIP-98 verifier so `did:nostr` agents authenticate identically to
    // every other endpoint.
    let pubkey = crate::extract_pubkey(&req).await;
    let web_id = crate::agent_uri(pubkey.as_ref());

    // Federation depth (consumed by call_remote_pod to enforce the cap).
    let federation_depth = req
        .headers()
        .get("mcp-federation-depth")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0);

    let ctx = McpCtx {
        web_id,
        origin: origin_of(&req),
        federation_depth,
    };

    // Streaming tool (subscribe)? Upgrade to SSE before normal dispatch.
    if !parsed.is_array() && tools::is_streaming_call(&parsed) {
        return tools::handle_subscribe(&parsed, state.get_ref().clone(), ctx).await;
    }

    // Batch (array of requests).
    if let Some(arr) = parsed.as_array() {
        let mut out: Vec<Value> = Vec::new();
        for msg in arr {
            if let Some(r) = dispatch(msg, state.get_ref(), &ctx).await {
                out.push(r);
            }
        }
        return HttpResponse::Ok().json(out);
    }

    match dispatch(&parsed, state.get_ref(), &ctx).await {
        // Notification — no response body.
        None => HttpResponse::NoContent().finish(),
        Some(result) => HttpResponse::Ok().json(result),
    }
}

/// `OPTIONS /mcp` — advertise the single supported method.
pub async fn handle_mcp_options() -> HttpResponse {
    HttpResponse::NoContent()
        .insert_header(("Allow", "POST, OPTIONS"))
        .finish()
}
