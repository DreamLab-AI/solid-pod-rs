//! Layered config loader.
//!
//! Precedence (later overrides earlier):
//!
//! ```text
//! Defaults < File < EnvVars < CLI
//! ```
//!
//! Matches JSS `src/config.js:211-239`. Sprint 11 (row 120-124) closes
//! the remaining gap by adding the CLI overlay, YAML/TOML file support
//! (via the `config-loader` feature), and the full JSS env-var map.
//!
//! The loader:
//!
//! 1. Walks the registered sources in order.
//! 2. Resolves each into a `serde_json::Value` tree.
//! 3. Deep-merges each overlay into the accumulator.
//! 4. Deserialises into [`ServerConfig`].
//! 5. Runs [`ServerConfig::validate`] and returns the snapshot.
//!
//! Unknown JSON fields are tolerated (every sub-struct uses
//! `#[serde(default)]`), matching the "forward-compat with newer JSS
//! releases" invariant in the bounded-context doc.

use std::path::{Path, PathBuf};

use serde_json::{Map, Value};

use crate::config::schema::ServerConfig;
use crate::config::sources::{merge_json, resolve_source, ConfigSource};
use crate::error::PodError;

// ---------------------------------------------------------------------------
// ConfigLoader
// ---------------------------------------------------------------------------

/// Builder for a layered config load.
///
/// Sources are applied in the order they were registered. The typical
/// JSS-parity invocation is:
///
/// ```no_run
/// use solid_pod_rs::config::ConfigLoader;
///
/// # async fn run() -> Result<(), Box<dyn std::error::Error>> {
/// let cfg = ConfigLoader::new()
///     .with_defaults()
///     .with_file("config.json")
///     .with_env()
///     .load()
///     .await?;
/// # Ok(()) }
/// ```
#[derive(Clone)]
pub struct ConfigLoader {
    sources: Vec<ConfigSource>,
    warnings: Vec<String>,
}

impl Default for ConfigLoader {
    fn default() -> Self {
        Self::new()
    }
}

impl ConfigLoader {
    /// Empty loader — add sources explicitly. Prefer
    /// [`Self::with_defaults`] as the first call so the final snapshot
    /// is always fully populated.
    pub fn new() -> Self {
        Self {
            sources: Vec::new(),
            warnings: Vec::new(),
        }
    }

    /// Register the hard-coded defaults as the lowest-precedence
    /// layer. Idempotent — calling twice has no additional effect.
    pub fn with_defaults(mut self) -> Self {
        if !self
            .sources
            .iter()
            .any(|s| matches!(s, ConfigSource::Defaults))
        {
            self.sources.push(ConfigSource::Defaults);
        }
        self
    }

    /// Register a config file source. Format is auto-detected from the
    /// extension: `.json` (always supported), `.yaml`/`.yml`, `.toml`
    /// (requires the `config-loader` feature). Missing / malformed
    /// files are a hard error at load time.
    pub fn with_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.sources.push(ConfigSource::File(path.into()));
        self
    }

    /// Register the process environment as a source. Reads `JSS_*`
    /// vars via [`std::env::var`].
    pub fn with_env(mut self) -> Self {
        self.sources.push(ConfigSource::EnvVars);
        self
    }

    /// Builder alias matching Sprint 11 naming — mutates the loader
    /// in-place and returns `&mut Self` so operator scripts can chain
    /// overlays without rebinding. Equivalent to [`Self::with_env`] on
    /// a mutable loader.
    pub fn with_env_overlay(&mut self) -> &mut Self {
        if !self
            .sources
            .iter()
            .any(|s| matches!(s, ConfigSource::EnvVars))
        {
            self.sources.push(ConfigSource::EnvVars);
        }
        self
    }

    /// Register a CLI args overlay as the highest-precedence layer.
    ///
    /// Precedence: Defaults < File < Env < **CLI**.
    ///
    /// The binary crate (clap) is the canonical caller; passing
    /// [`CliArgs::default()`] is a no-op overlay (every field `None`).
    pub fn with_cli_overlay(&mut self, args: &CliArgs) -> &mut Self {
        self.sources
            .push(ConfigSource::CliOverlay(args.to_overlay()));
        self
    }

    /// Load a config snapshot directly from a single file path,
    /// bypassing the builder. Format auto-detected from extension. This
    /// is the Sprint 11 row 120 one-shot helper — equivalent to
    /// `ConfigLoader::new().with_defaults().with_file(path).load()`.
    pub fn from_file<P: AsRef<Path>>(path: P) -> impl std::future::Future<Output = Result<ServerConfig, PodError>> {
        let p = path.as_ref().to_path_buf();
        async move {
            ConfigLoader::new()
                .with_defaults()
                .with_file(p)
                .load()
                .await
        }
    }

    /// Resolve all sources in order, merge them, deserialise, and
    /// validate.
    ///
    /// `async` for symmetry with JSS's `loadConfig` and to leave room
    /// for an eventual remote-config source (e.g. Consul, Vault)
    /// without another breaking change. No `await` points today.
    pub async fn load(mut self) -> Result<ServerConfig, PodError> {
        // If no sources were registered at all, inject Defaults so the
        // merged tree is always complete before the final deser pass.
        if self.sources.is_empty() {
            self.sources.push(ConfigSource::Defaults);
        }

        let mut tree = Value::Object(Default::default());

        for source in &self.sources {
            let overlay = resolve_source(source)?;
            merge_json(&mut tree, overlay);

            // Cross-source warning: JSS_STORAGE_TYPE=memory +
            // JSS_STORAGE_ROOT set. The env loader already dropped the
            // root value on our side, but we warn the operator.
            if let ConfigSource::EnvVars = source {
                let type_is_memory = tree
                    .get("storage")
                    .and_then(|s| s.get("type"))
                    .and_then(|t| t.as_str())
                    == Some("memory");
                let root_was_set = std::env::var("JSS_STORAGE_ROOT").is_ok()
                    || std::env::var("JSS_ROOT").is_ok();
                if type_is_memory && root_was_set {
                    self.warnings.push(
                        "JSS_STORAGE_TYPE=memory with JSS_STORAGE_ROOT/JSS_ROOT set: \
                         memory backend wins, root ignored"
                            .to_string(),
                    );
                }
            }
        }

        // Emit warnings via `tracing` if the operator has a subscriber
        // installed; no-op otherwise.
        for w in &self.warnings {
            tracing::warn!(target: "solid_pod_rs::config", "{w}");
        }

        let cfg: ServerConfig = serde_json::from_value(tree).map_err(|e| {
            PodError::Backend(format!("config merge produced invalid shape: {e}"))
        })?;

        cfg.validate().map_err(PodError::Backend)?;

        Ok(cfg)
    }

    /// Accessor for emitted warnings. Populated as a side-effect of
    /// [`Self::load`] if it is called; empty otherwise. Provided so
    /// test code can assert on warning behaviour without relying on a
    /// `tracing` subscriber.
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }
}

// ---------------------------------------------------------------------------
// CLI overlay — the top of the precedence stack.
// ---------------------------------------------------------------------------

/// CLI-derived overlay values. Each field is `Option<_>` so the
/// operator can leave every flag unset (yielding a no-op overlay).
///
/// The binary crate (`solid-pod-rs-server/src/main.rs`) constructs this
/// from clap-parsed args and passes it to
/// [`ConfigLoader::with_cli_overlay`]. Framework-agnostic callers can
/// use the plain struct-literal form.
///
/// Sprint 11 (row 121): highest-precedence layer. The field set is the
/// subset of [`crate::config::schema::ServerConfig`] that CLI
/// operators routinely override at boot.
#[derive(Debug, Clone, Default)]
pub struct CliArgs {
    pub host: Option<String>,
    pub port: Option<u16>,
    pub base_url: Option<String>,
    pub storage_root: Option<String>,
    pub storage_type: Option<String>,
    pub oidc_enabled: Option<bool>,
    pub oidc_issuer: Option<String>,
    pub nip98_enabled: Option<bool>,
    pub base_domain: Option<String>,
    pub subdomains_enabled: Option<bool>,
}

impl CliArgs {
    /// Render as a sparse overlay JSON value. Only fields explicitly set
    /// appear; everything else is absent so the deep-merge leaves lower
    /// layers intact.
    pub(crate) fn to_overlay(&self) -> Value {
        let mut out = Map::new();
        let mut server = Map::new();
        let mut storage = Map::new();
        let mut auth = Map::new();
        let mut extras = Map::new();

        if let Some(v) = &self.host {
            server.insert("host".into(), Value::String(v.clone()));
        }
        if let Some(v) = self.port {
            server.insert("port".into(), Value::Number(v.into()));
        }
        if let Some(v) = &self.base_url {
            server.insert("base_url".into(), Value::String(v.clone()));
        }
        if let Some(v) = &self.storage_type {
            storage.insert("type".into(), Value::String(v.clone()));
        }
        if let Some(v) = &self.storage_root {
            storage.insert("type".into(), Value::String("fs".into()));
            storage.insert("root".into(), Value::String(v.clone()));
        }
        if let Some(v) = self.oidc_enabled {
            auth.insert("oidc_enabled".into(), Value::Bool(v));
        }
        if let Some(v) = &self.oidc_issuer {
            auth.insert("oidc_issuer".into(), Value::String(v.clone()));
        }
        if let Some(v) = self.nip98_enabled {
            auth.insert("nip98_enabled".into(), Value::Bool(v));
        }
        if let Some(v) = &self.base_domain {
            extras.insert("base_domain".into(), Value::String(v.clone()));
        }
        if let Some(v) = self.subdomains_enabled {
            extras.insert("subdomains_enabled".into(), Value::Bool(v));
        }

        if !server.is_empty() {
            out.insert("server".into(), Value::Object(server));
        }
        if !storage.is_empty() {
            out.insert("storage".into(), Value::Object(storage));
        }
        if !auth.is_empty() {
            out.insert("auth".into(), Value::Object(auth));
        }
        if !extras.is_empty() {
            out.insert("extras".into(), Value::Object(extras));
        }

        Value::Object(out)
    }
}
