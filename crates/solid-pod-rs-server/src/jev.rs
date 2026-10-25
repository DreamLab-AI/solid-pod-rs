//! Jev option: opt-in typed decisions (TypeSafe System One) for the MCP surface.
//!
//! Compiled only with the `jev` cargo feature (off by default) and active only
//! when `SOLID_POD_JEV=1`. The core `solid-pod-rs` library does no network I/O
//! and is untouched; every byte that could leave the process is built here, in
//! the server crate, over the `reqwest` stack the server already depends on.
//!
//! Two consumers use this module:
//!
//! * **SP-08-S1-01** – rerank the already-authorised children of an LDP
//!   container for a free-text `query` (Score per candidate + one Noul).
//! * **SP-03-S1-01** – *propose* (never execute) an LDP operation and target
//!   for a free-text request (Choice for the operation, Choice for the target,
//!   Noul for "the request is unambiguous").
//!
//! # Authority stays in code
//!
//! Callers filter by WAC **before** this module sees a candidate; the model
//! only ever sees opaque ids `c0..cN` and code maps them back. Nothing here
//! writes, signs or changes permissions, and every failure maps to a
//! [`Fallback`] that makes the caller return exactly what it returned before
//! the option existed.
//!
//! # Local-only
//!
//! Both consumers send metadata about private pod content, so they are
//! **local-only**: an explicit endpoint needs `SOLID_POD_JEV_LOCAL=1`, the
//! agentbox loopback proxy needs `AGENTBOX_SYSTEM_ONE_BACKEND_LOCAL=1`, and
//! the public vendor endpoint is never used by this consumer.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{json, Map, Value};

/// Question-set version for SP-08 rerank (logged on every call).
pub const QUESTION_SET_RANK: &str = "sp08-rank-v1";
/// Question-set version for SP-03 operation proposal (logged on every call).
pub const QUESTION_SET_OP: &str = "sp03-op-v1";
/// Hard transport deadline. Interactive path: no retries.
pub const DEADLINE: Duration = Duration::from_secs(4);
/// Most candidates ever sent in one request.
pub const MAX_CANDIDATES: usize = 20;
/// Default acceptance threshold for reranking (reorder only; unfitted).
pub const DEFAULT_RANK_MIN_CONFIDENCE: f64 = 0.25;

/// Why the Jev option fell back to the pre-change behaviour.
#[derive(Debug, Clone, PartialEq)]
pub enum Fallback {
    /// `SOLID_POD_JEV` is not `1`.
    FlagOff,
    /// No usable endpoint under the local-only rules.
    NoEndpoint,
    /// The deadline passed (or the connection failed).
    Timeout,
    /// Non-2xx status (including 429/529; there are no retries).
    Http(u16),
    /// Unparseable body, missing/ill-typed answers, key outside the offered set,
    /// or a selection the authorised candidates do not permit.
    Malformed,
    /// Confidence/probability below the acceptance threshold.
    LowConfidence,
    /// More candidates than [`MAX_CANDIDATES`].
    OverCap,
}

impl Fallback {
    /// Stable reason string used in the single log line.
    pub fn reason(&self) -> String {
        match self {
            Fallback::FlagOff => "flag-off".into(),
            Fallback::NoEndpoint => "no-endpoint".into(),
            Fallback::Timeout => "timeout".into(),
            Fallback::Http(c) => format!("http-{c}"),
            Fallback::Malformed => "malformed".into(),
            Fallback::LowConfidence => "low-confidence".into(),
            Fallback::OverCap => "over-cap".into(),
        }
    }
}

/// Resolved endpoint and thresholds.
#[derive(Debug, Clone)]
pub struct JevConfig {
    /// Full URL to `POST` to.
    pub endpoint: String,
    /// Model name.
    pub model: String,
    /// Bearer token; `None` for the loopback proxy (it holds the vendor key).
    pub bearer: Option<String>,
    /// Hard deadline.
    pub timeout: Duration,
    /// Minimum mean Score confidence for a rerank to be applied.
    pub rank_min_confidence: f64,
    /// Minimum Choice confidence to accept an operation proposal.
    /// `None` (the default) accepts nothing automatically.
    pub op_min_confidence: Option<f64>,
}

/// Whether `SOLID_POD_JEV=1` in `env`.
pub fn flag_on(env: &dyn Fn(&str) -> Option<String>) -> bool {
    env("SOLID_POD_JEV").as_deref() == Some("1")
}

/// Resolve the endpoint (contract §2) for a **local-only** consumer.
///
/// Order: flag → explicit config (needs `SOLID_POD_JEV_LOCAL=1`) → agentbox
/// proxy (needs `AGENTBOX_SYSTEM_ONE_BACKEND_LOCAL=1`, sends no auth header) →
/// otherwise unavailable. The public vendor endpoint is deliberately never a
/// candidate here.
pub fn resolve(env: &dyn Fn(&str) -> Option<String>) -> Result<JevConfig, Fallback> {
    if !flag_on(env) {
        return Err(Fallback::FlagOff);
    }
    let get = |k: &str| env(k).filter(|v| !v.trim().is_empty());
    let rank_min = get("SOLID_POD_JEV_RANK_MIN_CONFIDENCE")
        .and_then(|v| v.parse::<f64>().ok())
        .filter(|v| (0.0..=1.0).contains(v))
        .unwrap_or(DEFAULT_RANK_MIN_CONFIDENCE);
    let op_min = get("SOLID_POD_JEV_OP_MIN_CONFIDENCE")
        .and_then(|v| v.parse::<f64>().ok())
        .filter(|v| *v > 0.0 && *v <= 1.0);
    let timeout = get("SOLID_POD_JEV_TIMEOUT_MS")
        .and_then(|v| v.parse::<u64>().ok())
        .map(Duration::from_millis)
        .map(|d| d.min(DEADLINE))
        .unwrap_or(DEADLINE);

    if let Some(endpoint) = get("SOLID_POD_JEV_ENDPOINT") {
        if get("SOLID_POD_JEV_LOCAL").as_deref() != Some("1") {
            return Err(Fallback::NoEndpoint);
        }
        let bearer = get("SOLID_POD_JEV_KEY_ENV").and_then(|name| get(&name));
        return Ok(JevConfig {
            endpoint,
            model: get("SOLID_POD_JEV_MODEL").unwrap_or_else(|| "jev-latest".into()),
            bearer,
            timeout,
            rank_min_confidence: rank_min,
            op_min_confidence: op_min,
        });
    }
    if get("AGENTBOX_SYSTEM_ONE_PROXY").as_deref() == Some("1")
        && get("AGENTBOX_SYSTEM_ONE_BACKEND_LOCAL").as_deref() == Some("1")
    {
        if let (Some(endpoint), Some(model)) = (
            get("AGENTBOX_SYSTEM_ONE_ENDPOINT"),
            get("AGENTBOX_SYSTEM_ONE_MODEL"),
        ) {
            return Ok(JevConfig {
                endpoint,
                model,
                bearer: None,
                timeout,
                rank_min_confidence: rank_min,
                op_min_confidence: op_min,
            });
        }
    }
    Err(Fallback::NoEndpoint)
}

/// HTTP transport seam (mockable in tests).
#[async_trait]
pub trait JevTransport: Send + Sync {
    /// `POST` `body` (JSON bytes) and return `(status, body)`, or the
    /// fallback for a transport failure ([`Fallback::Timeout`]).
    async fn post(&self, cfg: &JevConfig, body: Vec<u8>) -> Result<(u16, Vec<u8>), Fallback>;
}

/// Production transport over the workspace's `reqwest` (rustls, no retries).
pub struct ReqwestTransport;

#[async_trait]
impl JevTransport for ReqwestTransport {
    async fn post(&self, cfg: &JevConfig, body: Vec<u8>) -> Result<(u16, Vec<u8>), Fallback> {
        let client = reqwest::Client::builder()
            .timeout(cfg.timeout)
            .connect_timeout(cfg.timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| Fallback::NoEndpoint)?;
        let mut req = client
            .post(&cfg.endpoint)
            .header("Content-Type", "application/json")
            .body(body);
        if let Some(token) = &cfg.bearer {
            req = req.header("Authorization", format!("Bearer {token}"));
        }
        let resp = req.send().await.map_err(|_| Fallback::Timeout)?;
        let status = resp.status().as_u16();
        let bytes = resp.bytes().await.map_err(|_| Fallback::Timeout)?;
        // Bound what we will parse; a System One answer set is tiny.
        if bytes.len() > 1 << 20 {
            return Err(Fallback::Malformed);
        }
        Ok((status, bytes.to_vec()))
    }
}

/// Configuration result plus transport; built per call from the process
/// environment in production, injected in tests.
#[derive(Clone)]
pub struct JevRuntime {
    /// `Err` carries the reason Jev is unavailable.
    pub config: Result<JevConfig, Fallback>,
    /// Transport used for the single request.
    pub transport: Arc<dyn JevTransport>,
}

impl JevRuntime {
    /// Resolve from the real process environment.
    pub fn from_process_env() -> Self {
        Self {
            config: resolve(&|k| std::env::var(k).ok()),
            transport: Arc::new(ReqwestTransport),
        }
    }
}

/// `true` when the option is switched on in the process environment. Gates
/// the `propose_operation` tool's visibility.
pub fn enabled_in_process_env() -> bool {
    flag_on(&|k| std::env::var(k).ok())
}

fn log_outcome(question_set: &str, outcome: &Result<(), Fallback>) {
    match outcome {
        Ok(()) => tracing::info!(target: "jev", question_set, "accepted"),
        Err(Fallback::FlagOff) => {
            tracing::debug!(target: "jev", question_set, reason = "flag-off", "fallback")
        }
        Err(f) => tracing::info!(target: "jev", question_set, reason = %f.reason(), "fallback"),
    }
}

/// Send one request and return the `answers` object (contract §3 triggers).
async fn call(
    cfg: &JevConfig,
    transport: &dyn JevTransport,
    request: &Value,
) -> Result<Map<String, Value>, Fallback> {
    let body = serde_json::to_vec(request).map_err(|_| Fallback::Malformed)?;
    let (status, bytes) = transport.post(cfg, body).await?;
    if !(200..300).contains(&status) {
        return Err(Fallback::Http(status));
    }
    let v: Value = serde_json::from_slice(&bytes).map_err(|_| Fallback::Malformed)?;
    match v.get("answers") {
        Some(Value::Object(m)) if !m.is_empty() => Ok(m.clone()),
        _ => Err(Fallback::Malformed),
    }
}

fn answer<'a>(answers: &'a Map<String, Value>, id: &str, ty: &str) -> Result<&'a Value, Fallback> {
    let a = answers.get(id).ok_or(Fallback::Malformed)?;
    if a.get("type").and_then(Value::as_str) != Some(ty) {
        return Err(Fallback::Malformed);
    }
    Ok(a)
}

fn unit(v: Option<&Value>) -> Option<f64> {
    v.and_then(Value::as_f64)
        .filter(|x| x.is_finite() && (0.0..=1.0).contains(x))
}

/// Selected key and its confidence from a Choice answer; the key must be in
/// `allowed`. Confidence falls back to the documented
/// `(p - 1/n) / (1 - 1/n)` when the field is absent.
fn choice(
    answers: &Map<String, Value>,
    id: &str,
    allowed: &[String],
) -> Result<(String, f64), Fallback> {
    let a = answer(answers, id, "choice")?;
    let key = a
        .get("choice")
        .and_then(Value::as_str)
        .ok_or(Fallback::Malformed)?;
    if !allowed.iter().any(|k| k == key) {
        return Err(Fallback::Malformed);
    }
    let conf = match unit(a.get("confidence")) {
        Some(c) => c,
        None => {
            let p =
                unit(a.get("probabilities").and_then(|m| m.get(key))).ok_or(Fallback::Malformed)?;
            let n = allowed.len() as f64;
            if n < 2.0 {
                return Err(Fallback::Malformed);
            }
            ((p - 1.0 / n) / (1.0 - 1.0 / n)).clamp(0.0, 1.0)
        }
    };
    Ok((key.to_string(), conf))
}

fn noul(answers: &Map<String, Value>, id: &str) -> Result<f64, Fallback> {
    unit(answer(answers, id, "noul")?.get("noul")).ok_or(Fallback::Malformed)
}

fn score(answers: &Map<String, Value>, id: &str, levels: usize) -> Result<(f64, f64), Fallback> {
    let a = answer(answers, id, "score")?;
    let s = a
        .get("score")
        .and_then(Value::as_f64)
        .filter(|s| s.is_finite() && *s >= 0.0 && *s <= (levels as f64 - 1.0))
        .ok_or(Fallback::Malformed)?;
    let c = unit(a.get("confidence")).ok_or(Fallback::Malformed)?;
    Ok((s, c))
}

// ---------------------------------------------------------------------------
// SP-08-S1-01: rerank
// ---------------------------------------------------------------------------

const RANK_LEVELS: [&str; 3] = [
    "Unrelated: the entry has nothing to do with the query",
    "Related but not what the query asks for",
    "Directly relevant: this entry is what the query is looking for",
];

/// A candidate the caller has **already** WAC-authorised.
#[derive(Debug, Clone)]
pub struct RankCandidate {
    /// Child name.
    pub name: String,
    /// Absolute pod path.
    pub path: String,
    /// Container flag.
    pub is_container: bool,
}

/// Accepted rerank.
#[derive(Debug, Clone, PartialEq)]
pub struct RankOutcome {
    /// Candidate indices, best first; identity when `no_suitable`.
    pub order: Vec<usize>,
    /// Per-candidate expected score (0..=2), by original index.
    pub scores: Vec<f64>,
    /// Probability that no candidate suits the query.
    pub no_suitable: f64,
}

/// Build the System One request for a rerank (criteria: ordered list).
pub fn rank_request(model: &str, query: &str, cands: &[RankCandidate]) -> Value {
    let mut state_c = Map::new();
    let mut questions = Map::new();
    for (i, c) in cands.iter().enumerate() {
        state_c.insert(
            format!("c{i}"),
            json!({ "name": c.name, "path": c.path, "is_container": c.is_container }),
        );
        questions.insert(
            format!("rel_c{i}"),
            json!({
                "type": "score",
                "instructions": format!(
                    "Rate how directly the pod resource `candidates.c{i}` (judge by its name and path only) is what the user's `query` is looking for."
                ),
                "criteria": RANK_LEVELS,
            }),
        );
    }
    questions.insert(
        "no_suitable".into(),
        json!({
            "type": "noul",
            "instructions": "Is it true that none of the entries in `candidates` is a suitable answer to the user's `query`?"
        }),
    );
    json!({ "model": model, "state": { "query": query, "candidates": state_c }, "questions": questions })
}

/// Validate a rerank response (contract §3) and compute the new order.
pub fn rank_apply(
    answers: &Map<String, Value>,
    n: usize,
    min_confidence: f64,
) -> Result<RankOutcome, Fallback> {
    let mut scores = Vec::with_capacity(n);
    let mut conf_sum = 0.0;
    for i in 0..n {
        let (s, c) = score(answers, &format!("rel_c{i}"), RANK_LEVELS.len())?;
        scores.push(s);
        conf_sum += c;
    }
    let no_suitable = noul(answers, "no_suitable")?;
    if n > 0 && conf_sum / (n as f64) < min_confidence {
        return Err(Fallback::LowConfidence);
    }
    let mut order: Vec<usize> = (0..n).collect();
    if no_suitable < 0.5 {
        // Stable: ties keep their original relative order.
        order.sort_by(|a, b| {
            scores[*b]
                .partial_cmp(&scores[*a])
                .unwrap_or(std::cmp::Ordering::Equal)
        });
    }
    Ok(RankOutcome {
        order,
        scores,
        no_suitable,
    })
}

/// Run a rerank end to end. `Err` means "return the pre-change result".
pub async fn rank(
    rt: &JevRuntime,
    query: &str,
    cands: &[RankCandidate],
) -> Result<RankOutcome, Fallback> {
    let res = async {
        let cfg = rt.config.as_ref().map_err(Clone::clone)?;
        if cands.is_empty() {
            return Err(Fallback::Malformed);
        }
        if cands.len() > MAX_CANDIDATES {
            return Err(Fallback::OverCap);
        }
        let req = rank_request(&cfg.model, query, cands);
        let answers = call(cfg, rt.transport.as_ref(), &req).await?;
        rank_apply(&answers, cands.len(), cfg.rank_min_confidence)
    }
    .await;
    log_outcome(
        QUESTION_SET_RANK,
        &res.as_ref().map(|_| ()).map_err(Clone::clone),
    );
    res
}

/// Reorder only the `readable` slots of `items` per `outcome`; unreadable
/// items keep their original positions. Returns the `jev` annotation.
pub fn apply_rank(items: &mut [Value], readable: &[bool], outcome: &RankOutcome) -> Value {
    let slots: Vec<usize> = readable
        .iter()
        .enumerate()
        .filter_map(|(i, r)| r.then_some(i))
        .collect();
    let originals: Vec<Value> = slots.iter().map(|s| items[*s].clone()).collect();
    for (slot, idx) in slots.iter().zip(outcome.order.iter()) {
        items[*slot] = originals[*idx].clone();
    }
    json!({
        "questionSet": QUESTION_SET_RANK,
        "noSuitable": outcome.no_suitable,
        "reranked": outcome.no_suitable < 0.5,
    })
}

// ---------------------------------------------------------------------------
// SP-03-S1-01: propose an operation
// ---------------------------------------------------------------------------

/// An authorised child plus the verbs WAC grants on it.
#[derive(Debug, Clone)]
pub struct OpCandidate {
    /// Absolute pod path.
    pub path: String,
    /// Name (metadata only; bodies are never sent).
    pub name: String,
    /// Container flag.
    pub is_container: bool,
    /// WAC read granted.
    pub can_read: bool,
    /// WAC write granted.
    pub can_write: bool,
    /// WAC append (or write) granted.
    pub can_append: bool,
}

/// What WAC allows on the container itself.
#[derive(Debug, Clone, Copy)]
pub struct ContainerPerms {
    /// Write granted.
    pub can_write: bool,
    /// Append (or write) granted.
    pub can_append: bool,
}

/// A proposed operation. Never executed by this module.
#[derive(Debug, Clone, PartialEq)]
pub struct Proposal {
    /// `read`, `create`, `append`, `patch_preview`, `copy` or `clarify`.
    pub operation: String,
    /// Grounded absolute path, or `None` for `clarify`.
    pub target: Option<String>,
    /// Operation Choice confidence; `None` for the baseline.
    pub confidence: Option<f64>,
    /// `jev` or `baseline`.
    pub source: &'static str,
}

impl Proposal {
    /// The deterministic pre-Jev answer: ask the user to clarify.
    pub fn baseline() -> Self {
        Self {
            operation: "clarify".into(),
            target: None,
            confidence: None,
            source: "baseline",
        }
    }
    /// JSON form returned by the MCP tool.
    pub fn to_json(&self) -> Value {
        let mut o =
            json!({ "operation": self.operation, "target": self.target, "source": self.source });
        if let Some(c) = self.confidence {
            o["confidence"] = json!(c);
        }
        o
    }
}

/// Operations WAC permits given the authorised candidates (always includes
/// `clarify`). Order is stable.
pub fn allowed_operations(cands: &[OpCandidate], container: ContainerPerms) -> Vec<&'static str> {
    let mut ops = Vec::new();
    if cands.iter().any(|c| c.can_read && !c.is_container) {
        ops.push("read");
    }
    if container.can_append {
        ops.push("create");
    }
    if cands.iter().any(|c| c.can_append && !c.is_container) {
        ops.push("append");
    }
    if cands.iter().any(|c| c.can_write && !c.is_container) {
        ops.push("patch_preview");
    }
    if container.can_write && cands.iter().any(|c| c.can_read && !c.is_container) {
        ops.push("copy");
    }
    ops.push("clarify");
    ops
}

fn op_description(op: &str) -> &'static str {
    match op {
        "read" => "The user wants to read or view the content of one existing resource.",
        "create" => "The user wants to create a new resource in the container.",
        "append" => "The user wants to add content to the end of one existing resource without removing anything.",
        "patch_preview" => "The user wants to change part of one existing resource; only a preview of a non-destructive patch will be shown.",
        "copy" => "The user wants to duplicate one existing resource into the container.",
        _ => "The request is unclear, or none of the other operations fits, or the user must say more before anything is done.",
    }
}

/// Build the System One request for an operation proposal (criteria: maps).
pub fn op_request(
    model: &str,
    request: &str,
    container_path: &str,
    cands: &[OpCandidate],
    ops: &[&str],
) -> Value {
    let mut state_c = Map::new();
    let mut target_criteria = Map::new();
    for (i, c) in cands.iter().enumerate() {
        state_c.insert(
            format!("c{i}"),
            json!({ "name": c.name, "path": c.path, "is_container": c.is_container }),
        );
        target_criteria.insert(
            format!("c{i}"),
            Value::String(format!(
                "The request is about the resource `candidates.c{i}`."
            )),
        );
    }
    target_criteria.insert(
        "none".into(),
        Value::String("The request is not about any one listed resource (for example it creates something new, or is unclear).".into()),
    );
    let mut op_criteria = Map::new();
    for op in ops {
        op_criteria.insert((*op).into(), Value::String(op_description(op).into()));
    }
    json!({
        "model": model,
        "state": { "request": request, "container": container_path, "candidates": state_c },
        "questions": {
            "operation": {
                "type": "choice",
                "instructions": "Which single operation on the pod does the user's `request` ask for, within `container`? Only the listed operations are permitted for this user.",
                "criteria": op_criteria,
            },
            "target": {
                "type": "choice",
                "instructions": "Which one resource among `candidates` is the user's `request` about, if any?",
                "criteria": target_criteria,
            },
            "unambiguous": {
                "type": "noul",
                "instructions": "Is it true that the user's `request` is specific enough that a single operation on a single resource is clearly intended?"
            }
        }
    })
}

/// Validate an operation response and ground it against what WAC allows.
/// `min_confidence = None` accepts nothing.
pub fn op_apply(
    answers: &Map<String, Value>,
    container_path: &str,
    cands: &[OpCandidate],
    ops: &[&str],
    min_confidence: Option<f64>,
) -> Result<Proposal, Fallback> {
    let op_keys: Vec<String> = ops.iter().map(|s| s.to_string()).collect();
    let (op, op_conf) = choice(answers, "operation", &op_keys)?;
    let mut tgt_keys: Vec<String> = (0..cands.len()).map(|i| format!("c{i}")).collect();
    tgt_keys.push("none".into());
    let (tgt, tgt_conf) = choice(answers, "target", &tgt_keys)?;
    let unambiguous = noul(answers, "unambiguous")?;

    // Structural validation first (a wrong shape is malformed, not merely unsure).
    let idx = tgt.strip_prefix('c').and_then(|n| n.parse::<usize>().ok());
    let grounded: Option<String> = match (op.as_str(), idx) {
        ("clarify", _) => None,
        ("create", _) => Some(container_path.to_string()),
        ("read", Some(i)) if cands[i].can_read && !cands[i].is_container => {
            Some(cands[i].path.clone())
        }
        ("append", Some(i)) if cands[i].can_append && !cands[i].is_container => {
            Some(cands[i].path.clone())
        }
        ("patch_preview", Some(i)) if cands[i].can_write && !cands[i].is_container => {
            Some(cands[i].path.clone())
        }
        ("copy", Some(i)) if cands[i].can_read && !cands[i].is_container => {
            Some(cands[i].path.clone())
        }
        _ => return Err(Fallback::Malformed),
    };

    let Some(threshold) = min_confidence else {
        return Err(Fallback::LowConfidence);
    };
    let needs_target = !matches!(op.as_str(), "clarify" | "create");
    if op_conf < threshold || (needs_target && tgt_conf < threshold) || unambiguous < 0.5 {
        return Err(Fallback::LowConfidence);
    }
    Ok(Proposal {
        operation: op,
        target: grounded,
        confidence: Some(op_conf),
        source: "jev",
    })
}

/// Propose an operation. `Err` means "use [`Proposal::baseline`]".
pub async fn propose(
    rt: &JevRuntime,
    request: &str,
    container_path: &str,
    cands: &[OpCandidate],
    container: ContainerPerms,
) -> Result<Proposal, Fallback> {
    let res = async {
        let cfg = rt.config.as_ref().map_err(Clone::clone)?;
        if cands.len() > MAX_CANDIDATES {
            return Err(Fallback::OverCap);
        }
        let ops = allowed_operations(cands, container);
        if ops.len() < 2 {
            return Err(Fallback::Malformed);
        }
        let req = op_request(&cfg.model, request, container_path, cands, &ops);
        let answers = call(cfg, rt.transport.as_ref(), &req).await?;
        op_apply(&answers, container_path, cands, &ops, cfg.op_min_confidence)
    }
    .await;
    log_outcome(
        QUESTION_SET_OP,
        &res.as_ref().map(|_| ()).map_err(Clone::clone),
    );
    res
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let m: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |k| m.get(k).cloned()
    }

    #[test]
    fn resolve_flag_off_and_local_only_rules() {
        assert_eq!(resolve(&env(&[])).unwrap_err(), Fallback::FlagOff);
        assert_eq!(
            resolve(&env(&[
                ("SOLID_POD_JEV", "0"),
                ("SOLID_POD_JEV_ENDPOINT", "http://x")
            ]))
            .unwrap_err(),
            Fallback::FlagOff
        );
        // Explicit endpoint without `local = true` is refused.
        assert_eq!(
            resolve(&env(&[
                ("SOLID_POD_JEV", "1"),
                ("SOLID_POD_JEV_ENDPOINT", "http://x")
            ]))
            .unwrap_err(),
            Fallback::NoEndpoint
        );
        // Proxy without BACKEND_LOCAL is refused.
        assert_eq!(
            resolve(&env(&[
                ("SOLID_POD_JEV", "1"),
                ("AGENTBOX_SYSTEM_ONE_PROXY", "1"),
                ("AGENTBOX_SYSTEM_ONE_ENDPOINT", "http://p"),
                ("AGENTBOX_SYSTEM_ONE_MODEL", "m"),
            ]))
            .unwrap_err(),
            Fallback::NoEndpoint
        );
        // The public vendor endpoint is never used by a local-only consumer.
        assert_eq!(
            resolve(&env(&[("SOLID_POD_JEV", "1"), ("TYPESAFE_API_KEY", "k")])).unwrap_err(),
            Fallback::NoEndpoint
        );
        let c = resolve(&env(&[
            ("SOLID_POD_JEV", "1"),
            ("AGENTBOX_SYSTEM_ONE_PROXY", "1"),
            ("AGENTBOX_SYSTEM_ONE_BACKEND_LOCAL", "1"),
            ("AGENTBOX_SYSTEM_ONE_ENDPOINT", "http://p"),
            ("AGENTBOX_SYSTEM_ONE_MODEL", "m"),
        ]))
        .unwrap();
        assert_eq!(
            (c.endpoint.as_str(), c.model.as_str(), c.bearer.is_none()),
            ("http://p", "m", true)
        );
        let c = resolve(&env(&[
            ("SOLID_POD_JEV", "1"),
            ("SOLID_POD_JEV_ENDPOINT", "http://e"),
            ("SOLID_POD_JEV_LOCAL", "1"),
            ("SOLID_POD_JEV_KEY_ENV", "MY_KEY"),
            ("MY_KEY", "secret"),
        ]))
        .unwrap();
        assert_eq!(c.bearer.as_deref(), Some("secret"));
        assert_eq!(c.timeout, DEADLINE);
        assert!(
            c.op_min_confidence.is_none(),
            "default accepts nothing for operations"
        );
    }

    fn cfg(op_min: Option<f64>) -> JevConfig {
        JevConfig {
            endpoint: "http://mock".into(),
            model: "jev-latest".into(),
            bearer: None,
            timeout: DEADLINE,
            rank_min_confidence: 0.25,
            op_min_confidence: op_min,
        }
    }

    struct Mock {
        reply: Result<(u16, Vec<u8>), Fallback>,
        seen: Mutex<Vec<Vec<u8>>>,
    }
    impl Mock {
        fn ok(v: Value) -> Arc<Self> {
            Arc::new(Self {
                reply: Ok((200, serde_json::to_vec(&v).unwrap())),
                seen: Mutex::new(vec![]),
            })
        }
        fn raw(status: u16, b: &[u8]) -> Arc<Self> {
            Arc::new(Self {
                reply: Ok((status, b.to_vec())),
                seen: Mutex::new(vec![]),
            })
        }
        fn err(f: Fallback) -> Arc<Self> {
            Arc::new(Self {
                reply: Err(f),
                seen: Mutex::new(vec![]),
            })
        }
    }
    #[async_trait]
    impl JevTransport for Mock {
        async fn post(&self, _c: &JevConfig, body: Vec<u8>) -> Result<(u16, Vec<u8>), Fallback> {
            self.seen.lock().unwrap().push(body);
            self.reply.clone()
        }
    }
    fn rt(c: Result<JevConfig, Fallback>, m: &Arc<Mock>) -> JevRuntime {
        JevRuntime {
            config: c,
            transport: m.clone(),
        }
    }

    fn rcands() -> Vec<RankCandidate> {
        ["a.ttl", "b.ttl", "c.ttl"]
            .iter()
            .map(|n| RankCandidate {
                name: n.to_string(),
                path: format!("/p/{n}"),
                is_container: false,
            })
            .collect()
    }

    fn rank_reply(scores: [f64; 3], conf: f64, none: f64) -> Value {
        let mut a = Map::new();
        for (i, s) in scores.iter().enumerate() {
            a.insert(
                format!("rel_c{i}"),
                json!({"type":"score","score":s,"confidence":conf,"legend":{}}),
            );
        }
        a.insert("no_suitable".into(), json!({"type":"noul","noul":none}));
        json!({"model":"jev-latest","answers":a,"usage":{"input_tokens":1,"output_tokens":1}})
    }

    #[test]
    fn rank_wire_shape() {
        let r = rank_request("jev-latest", "my notes", &rcands());
        assert_eq!(r["model"], "jev-latest");
        assert!(r["state"]["candidates"].is_object());
        let q = r["questions"].as_object().unwrap();
        assert_eq!(q.len(), 4);
        assert_eq!(q["rel_c0"]["type"], "score");
        assert!(
            q["rel_c0"]["criteria"].is_array(),
            "Score criteria is an ordered list"
        );
        assert!(q["rel_c0"]["instructions"]
            .as_str()
            .unwrap()
            .contains("candidates.c0"));
        assert_eq!(q["no_suitable"]["type"], "noul");
    }

    #[actix_web::test]
    async fn rank_accept_and_reorder_keeps_unreadable_in_place() {
        let m = Mock::ok(rank_reply([0.2, 1.9, 1.0], 0.9, 0.1));
        let out = rank(&rt(Ok(cfg(None)), &m), "q", &rcands()).await.unwrap();
        assert_eq!(out.order, vec![1, 2, 0]);
        // items: [r0, hidden, r1, r2]; readable slots 0,2,3.
        let mut items = vec![json!("r0"), json!("hidden"), json!("r1"), json!("r2")];
        let note = apply_rank(&mut items, &[true, false, true, true], &out);
        assert_eq!(
            items,
            vec![json!("r1"), json!("hidden"), json!("r2"), json!("r0")]
        );
        assert_eq!(note["questionSet"], QUESTION_SET_RANK);
        assert_eq!(note["reranked"], true);
    }

    #[actix_web::test]
    async fn rank_no_suitable_annotates_without_reordering() {
        let m = Mock::ok(rank_reply([0.2, 1.9, 1.0], 0.9, 0.9));
        let out = rank(&rt(Ok(cfg(None)), &m), "q", &rcands()).await.unwrap();
        assert_eq!(out.order, vec![0, 1, 2]);
    }

    #[actix_web::test]
    async fn rank_every_fallback_trigger() {
        let good = rank_reply([0.2, 1.9, 1.0], 0.9, 0.1);
        let cases: Vec<(JevRuntime, Fallback)> = vec![
            (
                rt(Err(Fallback::FlagOff), &Mock::ok(good.clone())),
                Fallback::FlagOff,
            ),
            (
                rt(Err(Fallback::NoEndpoint), &Mock::ok(good.clone())),
                Fallback::NoEndpoint,
            ),
            (
                rt(Ok(cfg(None)), &Mock::err(Fallback::Timeout)),
                Fallback::Timeout,
            ),
            (
                rt(Ok(cfg(None)), &Mock::raw(429, b"{}")),
                Fallback::Http(429),
            ),
            (
                rt(Ok(cfg(None)), &Mock::raw(529, b"{}")),
                Fallback::Http(529),
            ),
            (
                rt(Ok(cfg(None)), &Mock::raw(500, b"{}")),
                Fallback::Http(500),
            ),
            (
                rt(Ok(cfg(None)), &Mock::raw(200, b"not json")),
                Fallback::Malformed,
            ),
            (
                rt(Ok(cfg(None)), &Mock::ok(json!({"answers":{}}))),
                Fallback::Malformed,
            ),
            (
                rt(
                    Ok(cfg(None)),
                    &Mock::ok(rank_reply([0.2, 1.9, 5.0], 0.9, 0.1)),
                ),
                Fallback::Malformed,
            ),
            (
                rt(
                    Ok(cfg(None)),
                    &Mock::ok(rank_reply([0.2, 1.9, 1.0], 0.05, 0.1)),
                ),
                Fallback::LowConfidence,
            ),
        ];
        for (r, want) in cases {
            assert_eq!(rank(&r, "q", &rcands()).await.unwrap_err(), want);
        }
        // Missing one answer id.
        let mut missing = rank_reply([0.2, 1.9, 1.0], 0.9, 0.1);
        missing["answers"].as_object_mut().unwrap().remove("rel_c1");
        assert_eq!(
            rank(&rt(Ok(cfg(None)), &Mock::ok(missing)), "q", &rcands())
                .await
                .unwrap_err(),
            Fallback::Malformed
        );
        // Wrong answer type.
        let mut wrong = rank_reply([0.2, 1.9, 1.0], 0.9, 0.1);
        wrong["answers"]["no_suitable"] = json!({"type":"score","score":1.0,"confidence":1.0});
        assert_eq!(
            rank(&rt(Ok(cfg(None)), &Mock::ok(wrong)), "q", &rcands())
                .await
                .unwrap_err(),
            Fallback::Malformed
        );
        // Over the candidate cap: no request is made.
        let many: Vec<RankCandidate> = (0..MAX_CANDIDATES + 1)
            .map(|i| RankCandidate {
                name: format!("{i}"),
                path: format!("/{i}"),
                is_container: false,
            })
            .collect();
        let m = Mock::ok(rank_reply([0.0; 3], 1.0, 0.0));
        assert_eq!(
            rank(&rt(Ok(cfg(None)), &m), "q", &many).await.unwrap_err(),
            Fallback::OverCap
        );
        assert!(m.seen.lock().unwrap().is_empty());
    }

    fn ocands() -> Vec<OpCandidate> {
        vec![
            OpCandidate {
                path: "/p/a.ttl".into(),
                name: "a.ttl".into(),
                is_container: false,
                can_read: true,
                can_write: true,
                can_append: true,
            },
            OpCandidate {
                path: "/p/b.ttl".into(),
                name: "b.ttl".into(),
                is_container: false,
                can_read: true,
                can_write: false,
                can_append: false,
            },
        ]
    }
    const PERMS: ContainerPerms = ContainerPerms {
        can_write: false,
        can_append: true,
    };

    fn op_reply(op: &str, tgt: &str, conf: f64, unamb: f64) -> Value {
        json!({"model":"m","answers":{
            "operation":{"type":"choice","choice":op,"confidence":conf,"probabilities":{}},
            "target":{"type":"choice","choice":tgt,"confidence":conf,"probabilities":{}},
            "unambiguous":{"type":"noul","noul":unamb}
        },"usage":{"input_tokens":1,"output_tokens":1}})
    }

    #[test]
    fn allowed_ops_follow_wac() {
        assert_eq!(
            allowed_operations(&ocands(), PERMS),
            vec!["read", "create", "append", "patch_preview", "clarify"]
        );
        assert_eq!(
            allowed_operations(
                &[],
                ContainerPerms {
                    can_write: false,
                    can_append: false
                }
            ),
            vec!["clarify"]
        );
    }

    #[test]
    fn op_wire_shape_criteria_are_maps_and_ids_present() {
        let ops = allowed_operations(&ocands(), PERMS);
        let r = op_request("jev-latest", "open b", "/p/", &ocands(), &ops);
        let q = r["questions"].as_object().unwrap();
        assert!(q["operation"]["criteria"].is_object());
        assert!(
            q["operation"]["criteria"].get("copy").is_none(),
            "copy not permitted here"
        );
        assert!(q["operation"]["criteria"].get("clarify").is_some());
        assert!(q["target"]["criteria"]
            .as_object()
            .unwrap()
            .contains_key("none"));
        assert_eq!(q["unambiguous"]["type"], "noul");
        // Only metadata, and only opaque ids in the target criteria.
        assert!(!r.to_string().contains("body"));
    }

    #[actix_web::test]
    async fn op_default_threshold_accepts_nothing() {
        let m = Mock::ok(op_reply("read", "c1", 0.99, 0.99));
        let e = propose(&rt(Ok(cfg(None)), &m), "open b", "/p/", &ocands(), PERMS)
            .await
            .unwrap_err();
        assert_eq!(e, Fallback::LowConfidence);
    }

    #[actix_web::test]
    async fn op_accept_path_grounds_target() {
        let m = Mock::ok(op_reply("read", "c1", 0.9, 0.9));
        let p = propose(
            &rt(Ok(cfg(Some(0.5))), &m),
            "open b",
            "/p/",
            &ocands(),
            PERMS,
        )
        .await
        .unwrap();
        assert_eq!(p.operation, "read");
        assert_eq!(p.target.as_deref(), Some("/p/b.ttl"));
        assert_eq!(p.source, "jev");
        let m = Mock::ok(op_reply("create", "none", 0.9, 0.9));
        let p = propose(
            &rt(Ok(cfg(Some(0.5))), &m),
            "make one",
            "/p/",
            &ocands(),
            PERMS,
        )
        .await
        .unwrap();
        assert_eq!(
            (p.operation.as_str(), p.target.as_deref()),
            ("create", Some("/p/"))
        );
    }

    #[actix_web::test]
    async fn op_rejects_what_wac_does_not_allow() {
        // Choice key outside the offered set (copy is not permitted).
        let m = Mock::ok(op_reply("copy", "c0", 0.9, 0.9));
        assert_eq!(
            propose(&rt(Ok(cfg(Some(0.1))), &m), "r", "/p/", &ocands(), PERMS)
                .await
                .unwrap_err(),
            Fallback::Malformed
        );
        // patch_preview on c1, which has no write grant.
        let m = Mock::ok(op_reply("patch_preview", "c1", 0.9, 0.9));
        assert_eq!(
            propose(&rt(Ok(cfg(Some(0.1))), &m), "r", "/p/", &ocands(), PERMS)
                .await
                .unwrap_err(),
            Fallback::Malformed
        );
        // Target id outside the offered ids.
        let m = Mock::ok(op_reply("read", "c9", 0.9, 0.9));
        assert_eq!(
            propose(&rt(Ok(cfg(Some(0.1))), &m), "r", "/p/", &ocands(), PERMS)
                .await
                .unwrap_err(),
            Fallback::Malformed
        );
    }

    #[actix_web::test]
    async fn op_every_fallback_trigger_and_low_confidence() {
        let go = |m: Arc<Mock>, c: Result<JevConfig, Fallback>| async move {
            propose(&rt(c, &m), "r", "/p/", &ocands(), PERMS)
                .await
                .unwrap_err()
        };
        assert_eq!(
            go(
                Mock::ok(op_reply("read", "c1", 0.9, 0.9)),
                Err(Fallback::FlagOff)
            )
            .await,
            Fallback::FlagOff
        );
        assert_eq!(
            go(
                Mock::ok(op_reply("read", "c1", 0.9, 0.9)),
                Err(Fallback::NoEndpoint)
            )
            .await,
            Fallback::NoEndpoint
        );
        assert_eq!(
            go(Mock::err(Fallback::Timeout), Ok(cfg(Some(0.5)))).await,
            Fallback::Timeout
        );
        assert_eq!(
            go(Mock::raw(503, b"x"), Ok(cfg(Some(0.5)))).await,
            Fallback::Http(503)
        );
        assert_eq!(
            go(Mock::raw(200, b"<html>"), Ok(cfg(Some(0.5)))).await,
            Fallback::Malformed
        );
        assert_eq!(
            go(
                Mock::ok(op_reply("read", "c1", 0.2, 0.9)),
                Ok(cfg(Some(0.5)))
            )
            .await,
            Fallback::LowConfidence
        );
        assert_eq!(
            go(
                Mock::ok(op_reply("read", "c1", 0.9, 0.4)),
                Ok(cfg(Some(0.5)))
            )
            .await,
            Fallback::LowConfidence
        );
    }

    #[test]
    fn choice_confidence_derived_from_probabilities_when_absent() {
        let mut a = Map::new();
        a.insert(
            "q".into(),
            json!({"type":"choice","choice":"x","probabilities":{"x":0.6,"y":0.2,"z":0.2}}),
        );
        let (_, c) = choice(&a, "q", &["x".into(), "y".into(), "z".into()]).unwrap();
        assert!((c - 0.4).abs() < 1e-9);
    }

    #[test]
    fn baseline_shape() {
        assert_eq!(
            Proposal::baseline().to_json(),
            json!({"operation":"clarify","target":null,"source":"baseline"})
        );
    }

    #[actix_web::test]
    async fn reqwest_transport_sends_expected_wire_and_headers() {
        use wiremock::matchers::{header, method};
        use wiremock::{Mock as WMock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        WMock::given(method("POST"))
            .and(header("content-type", "application/json"))
            .and(header("authorization", "Bearer sekrit"))
            .respond_with(ResponseTemplate::new(200).set_body_json(rank_reply(
                [0.0, 2.0, 1.0],
                0.9,
                0.1,
            )))
            .mount(&server)
            .await;
        let mut c = cfg(None);
        c.endpoint = format!("{}/v1/systemone", server.uri());
        c.bearer = Some("sekrit".into());
        let r = JevRuntime {
            config: Ok(c),
            transport: Arc::new(ReqwestTransport),
        };
        let out = rank(&r, "q", &rcands()).await.unwrap();
        assert_eq!(out.order, vec![1, 2, 0]);
        let seen = server.received_requests().await.unwrap();
        assert_eq!(seen.len(), 1);
        let body: Value = serde_json::from_slice(&seen[0].body).unwrap();
        assert!(body["questions"]["rel_c0"]["criteria"].is_array());
    }

    #[actix_web::test]
    async fn reqwest_transport_times_out_to_fallback() {
        use wiremock::{Mock as WMock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        WMock::given(wiremock::matchers::any())
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_millis(600)))
            .mount(&server)
            .await;
        let mut c = cfg(None);
        c.endpoint = server.uri();
        c.timeout = Duration::from_millis(100);
        let r = JevRuntime {
            config: Ok(c),
            transport: Arc::new(ReqwestTransport),
        };
        assert_eq!(
            rank(&r, "q", &rcands()).await.unwrap_err(),
            Fallback::Timeout
        );
    }
}
