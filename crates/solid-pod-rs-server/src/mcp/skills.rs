//! Skill discovery for the MCP server.
//!
//! Skills are `SKILL.md` (or `SKILL.jsonld`) files at well-known paths:
//!
//!   `<pod>/SKILL.md`                       pod-wide
//!   `<pod>/public/apps/<name>/SKILL.md`    per-app
//!   `<pod>/private/bots/<name>/SKILL.md`   per-bot
//!
//! The discovery channel (`list_skills`) is stable; the payload format
//! declared via `skill:format` evolves (`anthropic.skill.v1` today,
//! future vocabularies plug in by name).
//!
//! Mirrors JSS `src/mcp/skills.js`.

use serde_json::{json, Value};
use solid_pod_rs::storage::Storage;

const POD_ROOT_SKILL: [&str; 2] = ["/SKILL.md", "/SKILL.jsonld"];
const APPS_BASE: &str = "/public/apps/";
const BOTS_BASE: &str = "/private/bots/";

fn format_for_path(path: &str) -> &'static str {
    if path.ends_with(".jsonld") {
        "jsonld"
    } else {
        "anthropic.skill.v1"
    }
}

fn scope_from_path(path: &str) -> &'static str {
    if path.starts_with(APPS_BASE) {
        "app"
    } else if path.starts_with(BOTS_BASE) {
        "bot"
    } else {
        "pod"
    }
}

async fn exists(storage: &dyn Storage, path: &str) -> bool {
    storage.exists(path).await.unwrap_or(false)
}

/// Build a skill index entry for `path` (or its `.jsonld` sibling).
async fn try_entry(storage: &dyn Storage, path: &str) -> Option<Value> {
    let jsonld = path.replace(".md", ".jsonld");
    for variant in [path.to_string(), jsonld] {
        if exists(storage, &variant).await {
            let size = storage
                .head(&variant)
                .await
                .ok()
                .map(|m| m.size)
                .map(Value::from)
                .unwrap_or(Value::Null);
            return Some(json!({
                "@id": variant,
                "skill:scope": scope_from_path(&variant),
                "skill:format": format_for_path(&variant),
                "skill:source": variant,
                "schema:contentSize": size,
            }));
        }
    }
    None
}

/// Names of the immediate sub-containers of `container_path`.
async fn list_container_names(storage: &dyn Storage, container_path: &str) -> Vec<String> {
    if !exists(storage, container_path).await {
        return Vec::new();
    }
    match storage.list(container_path).await {
        Ok(entries) => entries
            .into_iter()
            .filter(|e| e.ends_with('/'))
            .map(|e| e.trim_end_matches('/').to_string())
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// Walk the conventional skill locations and return a discovered-skills index.
pub async fn discover_skills(storage: &dyn Storage) -> Value {
    let mut items: Vec<Value> = Vec::new();

    // Pod-wide
    for p in POD_ROOT_SKILL {
        if exists(storage, p).await {
            items.push(json!({
                "@id": p,
                "skill:scope": "pod",
                "skill:format": format_for_path(p),
                "skill:source": p,
                "schema:name": "pod",
            }));
            break;
        }
    }

    // Apps
    for name in list_container_names(storage, APPS_BASE).await {
        let skill_path = format!("{APPS_BASE}{name}/SKILL.md");
        if let Some(mut skill) = try_entry(storage, &skill_path).await {
            skill["schema:name"] = json!(name);
            items.push(skill);
        }
    }

    // Bots
    for name in list_container_names(storage, BOTS_BASE).await {
        let skill_path = format!("{BOTS_BASE}{name}/SKILL.md");
        if let Some(mut skill) = try_entry(storage, &skill_path).await {
            skill["schema:name"] = json!(name);
            items.push(skill);
        }
    }

    json!({
        "@context": { "skill": "urn:skill:", "schema": "https://schema.org/" },
        "@type": "skill:SkillIndex",
        "skill:items": items,
    })
}

/// Read a single skill file by pod path. Returns `Err(message)` if missing.
pub async fn read_skill(storage: &dyn Storage, path: &str) -> Result<Value, String> {
    if path.is_empty() {
        return Err("skill path required".to_string());
    }
    let path = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    };
    if !exists(storage, &path).await {
        return Err(format!("skill not found: {path}"));
    }
    let (body, _meta) = storage
        .get(&path)
        .await
        .map_err(|e| format!("read failed: {e}"))?;
    Ok(json!({
        "path": path,
        "format": format_for_path(&path),
        "scope": scope_from_path(&path),
        "body": String::from_utf8_lossy(&body),
    }))
}

/// Read the pod-wide `SKILL.md` (or `.jsonld`). `None` if neither exists.
pub async fn read_pod_skill(storage: &dyn Storage) -> Option<Value> {
    for p in POD_ROOT_SKILL {
        if exists(storage, p).await {
            return read_skill(storage, p).await.ok();
        }
    }
    None
}
