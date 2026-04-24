//! Sprint 11 (rows 120-124) — config loader extensions.
//!
//! Covers the new surface introduced in Sprint 11:
//!
//! * `ConfigLoader::from_file` auto-detects JSON / YAML / TOML from the
//!   file extension.
//! * `with_cli_overlay` sits at the top of the precedence stack.
//! * `parse_size` now accepts IEC binary suffixes (`KiB`, `MiB`, `GiB`,
//!   `TiB`) in addition to the existing SI decimal set.
//! * The extended JSS env-var map covers 30+ `JSS_*` names.
//!
//! The tests use a shared mutex to serialise env mutations, same as the
//! Sprint-4 `config_test.rs` harness. No unrelated state is touched.

use solid_pod_rs::config::sources::parse_size;
use solid_pod_rs::config::{CliArgs, ConfigLoader, StorageBackendConfig};
use tokio::sync::Mutex;

static ENV_LOCK: Mutex<()> = Mutex::const_new(());

const JSS_ENV_VARS: &[&str] = &[
    "JSS_HOST",
    "JSS_PORT",
    "JSS_BASE_URL",
    "JSS_ROOT",
    "JSS_STORAGE_TYPE",
    "JSS_STORAGE_ROOT",
    "JSS_S3_BUCKET",
    "JSS_S3_REGION",
    "JSS_S3_PREFIX",
    "JSS_OIDC_ENABLED",
    "JSS_OIDC_ISSUER",
    "JSS_IDP",
    "JSS_IDP_ISSUER",
    "JSS_NIP98_ENABLED",
    "JSS_DPOP_REPLAY_TTL_SECONDS",
    "JSS_NOTIFICATIONS",
    "JSS_NOTIFICATIONS_WS2023",
    "JSS_NOTIFICATIONS_WEBHOOK",
    "JSS_NOTIFICATIONS_LEGACY",
    "JSS_SSRF_ALLOW_PRIVATE",
    "JSS_SSRF_ALLOWLIST",
    "JSS_SSRF_DENYLIST",
    "JSS_DOTFILE_ALLOWLIST",
    "JSS_ACL_ORIGIN_ENABLED",
    "JSS_DEFAULT_QUOTA",
    "JSS_QUOTA_DEFAULT_BYTES",
    "JSS_CONNEG",
    "JSS_CORS_ALLOWED_ORIGINS",
    "JSS_MAX_BODY_SIZE",
    "JSS_MAX_REQUEST_BODY",
    "JSS_MAX_ACL_BYTES",
    "JSS_RATE_LIMIT_WRITES_PER_MIN",
    "JSS_SUBDOMAINS",
    "JSS_BASE_DOMAIN",
    "JSS_IDP_ENABLED",
    "JSS_INVITE_ONLY",
    "JSS_ADMIN_KEY",
];

fn clear_jss_env() {
    for k in JSS_ENV_VARS {
        std::env::remove_var(k);
    }
}

// ---------------------------------------------------------------------------
// parse_size — binary (IEC) suffixes
// ---------------------------------------------------------------------------

#[test]
fn parse_size_bytes_bare_is_1024() {
    // Bare "1024" is treated as raw bytes.
    assert_eq!(parse_size("1024").unwrap(), 1024u64);
}

#[test]
fn parse_size_kib_is_1024() {
    assert_eq!(parse_size("1KiB").unwrap(), 1_024u64);
    assert_eq!(parse_size("1kib").unwrap(), 1_024u64);
    assert_eq!(parse_size(" 1 KiB ").unwrap(), 1_024u64);
}

#[test]
fn parse_size_mib() {
    // 50MiB → 50 * 1024 * 1024
    assert_eq!(parse_size("50MiB").unwrap(), 50 * 1024 * 1024);
}

#[test]
fn parse_size_gib() {
    assert_eq!(parse_size("1GiB").unwrap(), 1024u64.pow(3));
}

#[test]
fn parse_size_tib() {
    assert_eq!(parse_size("1TiB").unwrap(), 1024u64.pow(4));
}

#[test]
fn parse_size_si_still_works() {
    // Sprint 7 decimal suffixes must keep their meaning.
    assert_eq!(parse_size("50MB").unwrap(), 50_000_000u64);
    assert_eq!(parse_size("1.5GB").unwrap(), 1_500_000_000u64);
}

// ---------------------------------------------------------------------------
// YAML file loader
// ---------------------------------------------------------------------------

#[cfg(feature = "config-loader")]
#[tokio::test]
async fn config_yaml_loader() {
    let _guard = ENV_LOCK.lock().await;
    clear_jss_env();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.yaml");
    std::fs::write(
        &path,
        r#"
server:
  host: "127.0.0.1"
  port: 4242
auth:
  nip98_enabled: false
"#,
    )
    .unwrap();

    let cfg = ConfigLoader::from_file(&path)
        .await
        .expect("YAML must load");
    assert_eq!(cfg.server.host, "127.0.0.1");
    assert_eq!(cfg.server.port, 4242);
    assert!(!cfg.auth.nip98_enabled);
}

// ---------------------------------------------------------------------------
// TOML file loader
// ---------------------------------------------------------------------------

#[cfg(feature = "config-loader")]
#[tokio::test]
async fn config_toml_loader() {
    let _guard = ENV_LOCK.lock().await;
    clear_jss_env();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(
        &path,
        r#"
[server]
host = "10.0.0.9"
port = 5555

[auth]
oidc_enabled = false
"#,
    )
    .unwrap();

    let cfg = ConfigLoader::from_file(&path)
        .await
        .expect("TOML must load");
    assert_eq!(cfg.server.host, "10.0.0.9");
    assert_eq!(cfg.server.port, 5555);
}

// ---------------------------------------------------------------------------
// JSON file loader (still works via from_file)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn config_json_loader_from_file() {
    let _guard = ENV_LOCK.lock().await;
    clear_jss_env();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.json");
    std::fs::write(
        &path,
        r#"{ "server": { "host": "0.0.0.0", "port": 4000 } }"#,
    )
    .unwrap();

    let cfg = ConfigLoader::from_file(&path)
        .await
        .expect("JSON must load");
    assert_eq!(cfg.server.port, 4000);
}

// ---------------------------------------------------------------------------
// CLI overlay — highest precedence
// ---------------------------------------------------------------------------

#[tokio::test]
async fn config_cli_overrides_env() {
    let _guard = ENV_LOCK.lock().await;
    clear_jss_env();

    std::env::set_var("JSS_HOST", "from-env");
    std::env::set_var("JSS_PORT", "4000");

    let cli = CliArgs {
        host: Some("from-cli".into()),
        port: Some(5000),
        ..Default::default()
    };

    let mut loader = ConfigLoader::new().with_defaults().with_env();
    loader.with_cli_overlay(&cli);

    let cfg = loader.load().await.expect("cli overlay load");

    assert_eq!(cfg.server.host, "from-cli");
    assert_eq!(cfg.server.port, 5000);

    clear_jss_env();
}

// ---------------------------------------------------------------------------
// Env overlay surfaces JSS_CORS_ALLOWED_ORIGINS / JSS_SUBDOMAINS /
// JSS_BASE_DOMAIN / JSS_IDP_ENABLED under `extras`.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn config_env_extras_populate() {
    let _guard = ENV_LOCK.lock().await;
    clear_jss_env();

    std::env::set_var("JSS_CORS_ALLOWED_ORIGINS", "https://a.example, https://b.example");
    std::env::set_var("JSS_SUBDOMAINS", "true");
    std::env::set_var("JSS_BASE_DOMAIN", "pods.example.com");
    std::env::set_var("JSS_IDP_ENABLED", "true");
    std::env::set_var("JSS_INVITE_ONLY", "yes");
    std::env::set_var("JSS_MAX_BODY_SIZE", "10MiB");

    let cfg = ConfigLoader::new()
        .with_defaults()
        .with_env()
        .load()
        .await
        .expect("extras env load");

    assert_eq!(
        cfg.extras.cors_allowed_origins,
        vec!["https://a.example".to_string(), "https://b.example".to_string()]
    );
    assert_eq!(cfg.extras.subdomains_enabled, Some(true));
    assert_eq!(cfg.extras.base_domain.as_deref(), Some("pods.example.com"));
    assert_eq!(cfg.extras.idp_enabled, Some(true));
    assert_eq!(cfg.extras.invite_only, Some(true));
    assert_eq!(cfg.extras.max_body_size_bytes, Some(10 * 1024 * 1024));

    clear_jss_env();
}

// ---------------------------------------------------------------------------
// Fs storage backend through storage_root CLI option.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn config_cli_storage_root_sets_fs() {
    let _guard = ENV_LOCK.lock().await;
    clear_jss_env();

    let cli = CliArgs {
        storage_root: Some("/srv/pods".into()),
        ..Default::default()
    };

    let mut loader = ConfigLoader::new().with_defaults();
    loader.with_cli_overlay(&cli);
    let cfg = loader.load().await.expect("cli storage load");

    assert!(matches!(
        cfg.storage,
        StorageBackendConfig::Fs { ref root } if root == "/srv/pods"
    ));
}
