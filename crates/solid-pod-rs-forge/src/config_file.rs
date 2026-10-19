//! JSON configuration layering: explicit config over a `FORGE_CONFIG` file.
//!
//! Mirrors the JSS `forge` activation: when the `FORGE_CONFIG` environment
//! variable names a JSON file its keys are merged in as *defaults* (an
//! explicitly supplied key always wins; an unset variable or an unreadable
//! file is a no-op that only logs). Keys use the JSS camelCase spelling
//! (`privateRepos`, `baseUrl`, `loopbackUrl`, `cspConnect`, `pushTokenTtl`,
//! `chain`, `allowMainnet`, `announceRelays`, `prefix`, `openEdit`).
//!
//! The loader takes an explicit path so tests never touch process
//! environment; [`ForgeConfig::from_env`] is the thin `FORGE_CONFIG` wrapper.

use std::path::Path;

use serde_json::Value;

use crate::config::ForgeConfig;
use crate::error::ForgeError;

/// Name of the environment variable that points at the defaults file.
pub const FORGE_CONFIG_ENV: &str = "FORGE_CONFIG";

/// Read and parse a JSON object from `path`.
///
/// # Errors
///
/// [`ForgeError::Io`] when unreadable, [`ForgeError::BadRequest`] when the
/// file is not a JSON object.
pub fn load_file(path: &Path) -> Result<Value, ForgeError> {
    let raw = std::fs::read_to_string(path)?;
    let v: Value = serde_json::from_str(&raw)?;
    if v.is_object() {
        Ok(v)
    } else {
        Err(ForgeError::BadRequest(
            "config file is not a JSON object".into(),
        ))
    }
}

/// Copy every key of `file` that `explicit` does not define into `explicit`
/// (JSS: "explicit `api.config` wins"). Non-object inputs are treated as
/// empty objects.
///
/// # Examples
///
/// ```
/// use serde_json::json;
/// use solid_pod_rs_forge::config_file::merge_defaults;
///
/// let merged = merge_defaults(json!({"privateRepos": true}), json!({"privateRepos": false, "baseUrl": "https://f.example"}));
/// assert_eq!(merged["privateRepos"], true);
/// assert_eq!(merged["baseUrl"], "https://f.example");
/// ```
#[must_use]
pub fn merge_defaults(explicit: Value, file: Value) -> Value {
    let mut out = match explicit {
        Value::Object(m) => m,
        _ => serde_json::Map::new(),
    };
    if let Value::Object(f) = file {
        for (k, v) in f {
            out.entry(k).or_insert(v);
        }
    }
    Value::Object(out)
}

fn str_list(v: &Value) -> Vec<String> {
    v.as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn opt_url(v: &Value) -> Option<String> {
    v.as_str()
        .map(|s| s.trim_end_matches('/').to_string())
        .filter(|s| !s.is_empty())
}

impl ForgeConfig {
    /// Build a config from a JSON object in the JSS key spelling. Unknown
    /// keys are ignored; absent keys keep their [`Default`].
    ///
    /// # Examples
    ///
    /// ```
    /// use serde_json::json;
    /// use solid_pod_rs_forge::ForgeConfig;
    ///
    /// let c = ForgeConfig::from_json(&json!({"privateRepos": true, "baseUrl": "https://f.example/", "cspConnect": ["https://idp.example"]}));
    /// assert!(c.private_repos);
    /// assert_eq!(c.base_url.as_deref(), Some("https://f.example"));
    /// assert_eq!(c.csp_connect, vec!["https://idp.example".to_string()]);
    /// ```
    #[must_use]
    pub fn from_json(v: &Value) -> Self {
        let mut c = Self::default();
        if let Some(p) = v.get("prefix").and_then(Value::as_str) {
            c.prefix = p.to_string();
        }
        if let Some(t) = v.get("pushTokenTtl").and_then(Value::as_u64) {
            c.token_ttl_secs = t;
        }
        if let Some(b) = v.get("privateRepos").and_then(Value::as_bool) {
            c.private_repos = b;
        }
        if let Some(ch) = v.get("chain").and_then(Value::as_str) {
            c.default_chain = ch.to_string();
        }
        if let Some(b) = v.get("allowMainnet").and_then(Value::as_bool) {
            c.allow_mainnet = b;
        }
        if let Some(x) = v.get("announceRelays") {
            c.announce_relays = str_list(x);
        }
        if let Some(x) = v.get("baseUrl") {
            c.base_url = opt_url(x);
        }
        if let Some(x) = v.get("loopbackUrl") {
            c.loopback_url = opt_url(x);
        }
        if let Some(x) = v.get("cspConnect") {
            c.csp_connect = str_list(x);
        }
        if let Some(b) = v.get("openEdit").and_then(Value::as_bool) {
            c.open_edit = b;
        }
        c
    }

    /// Layer an optional defaults file under `explicit` and build the config.
    /// A missing or unreadable file only logs a warning (JSS behaviour).
    #[must_use]
    pub fn from_layers(explicit: Value, defaults_file: Option<&Path>) -> Self {
        let merged = match defaults_file {
            Some(p) => match load_file(p) {
                Ok(file) => merge_defaults(explicit, file),
                Err(e) => {
                    tracing::warn!("forge: {FORGE_CONFIG_ENV} load failed: {e}");
                    explicit
                }
            },
            None => explicit,
        };
        Self::from_json(&merged)
    }

    /// [`from_layers`](Self::from_layers) with the file taken from the
    /// `FORGE_CONFIG` environment variable (unset or empty: no file).
    #[must_use]
    pub fn from_env(explicit: Value) -> Self {
        let path = std::env::var_os(FORGE_CONFIG_ENV).filter(|p| !p.is_empty());
        Self::from_layers(explicit, path.as_deref().map(Path::new))
    }

    /// The public origin: `base_url` when configured, else `fallback`
    /// (typically the request's `host_url`), without a trailing slash.
    #[must_use]
    pub fn public_origin(&self, fallback: Option<&str>) -> String {
        self.base_url
            .clone()
            .or_else(|| fallback.map(|f| f.trim_end_matches('/').to_string()))
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn explicit_wins_over_file_defaults() {
        let td = tempfile::TempDir::new().unwrap();
        let f = td.path().join("forge.json");
        std::fs::write(
            &f,
            r#"{"privateRepos": true, "baseUrl": "https://f.example/", "cspConnect": ["https://idp.example", 7], "pushTokenTtl": 99}"#,
        )
        .unwrap();
        let c = ForgeConfig::from_layers(json!({"privateRepos": false}), Some(&f));
        assert!(!c.private_repos, "explicit key wins");
        assert_eq!(c.base_url.as_deref(), Some("https://f.example"));
        assert_eq!(c.csp_connect, vec!["https://idp.example".to_string()]);
        assert_eq!(c.token_ttl_secs, 99);
    }

    #[test]
    fn missing_or_bad_file_is_a_no_op() {
        let td = tempfile::TempDir::new().unwrap();
        let c = ForgeConfig::from_layers(
            json!({"privateRepos": true}),
            Some(&td.path().join("nope.json")),
        );
        assert!(c.private_repos);
        let bad = td.path().join("bad.json");
        std::fs::write(&bad, "[1,2]").unwrap();
        let c = ForgeConfig::from_layers(json!({}), Some(&bad));
        assert!(!c.private_repos);
        std::fs::write(&bad, "not json").unwrap();
        assert!(load_file(&bad).is_err());
        let c = ForgeConfig::from_layers(json!({}), None);
        assert_eq!(c.prefix, "/forge");
    }

    #[test]
    fn keys_map_and_origin_resolution() {
        let c = ForgeConfig::from_json(&json!({
            "prefix": "/git", "chain": "signet", "allowMainnet": true,
            "announceRelays": ["wss://r.example"], "loopbackUrl": "http://127.0.0.1:3000/",
            "baseUrl": ""
        }));
        assert_eq!(c.prefix, "/git");
        assert_eq!(c.default_chain, "signet");
        assert!(c.allow_mainnet);
        assert_eq!(c.announce_relays, vec!["wss://r.example".to_string()]);
        assert_eq!(c.loopback_url.as_deref(), Some("http://127.0.0.1:3000"));
        assert_eq!(c.base_url, None, "empty baseUrl is unset");
        assert_eq!(
            c.public_origin(Some("https://h.example/")),
            "https://h.example"
        );
        let c2 = ForgeConfig::from_json(&json!({"baseUrl": "https://pub.example/"}));
        assert_eq!(
            c2.public_origin(Some("https://h.example")),
            "https://pub.example"
        );
        assert_eq!(ForgeConfig::default().public_origin(None), "");
    }
}
