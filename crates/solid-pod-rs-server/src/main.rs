//! `solid-pod-rs-server` — drop-in JSS replacement binary.
//!
//! Thin actix-web shell over [`solid_pod_rs`]. HTTP wiring and the full
//! route table live in [`solid_pod_rs_server::build_app`]; this file
//! owns only the process entry point: CLI parsing, tracing
//! initialisation, config loading, storage construction, signal
//! handling, and (optionally) TLS.

use std::sync::Arc;

use actix_web::HttpServer;
use anyhow::Context;
use clap::Parser;
use solid_pod_rs::{
    config::{ConfigLoader, ServerConfig, StorageBackendConfig},
    storage::{fs::FsBackend, memory::MemoryBackend, Storage},
};
use solid_pod_rs_server::{
    build_app,
    cli::{dispatch as dispatch_operator_cmd, OperatorCommand},
    AppState, NodeInfoMeta,
};
use tracing::{info, warn};

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

/// JSS-compatible Solid Pod server, implemented in Rust.
#[derive(Debug, Parser)]
#[command(
    name = "solid-pod-rs-server",
    version,
    about = "Drop-in JSS replacement — Solid Pod server binary",
    long_about = None,
)]
struct Cli {
    /// Path to a JSS-compatible `config.json` file. Optional.
    #[arg(long, short = 'c', env = "JSS_CONFIG")]
    config: Option<String>,

    /// Override `server.host` from config / env.
    #[arg(long)]
    host: Option<String>,

    /// Override `server.port` from config / env.
    #[arg(long, short = 'p')]
    port: Option<u16>,

    /// Tracing filter directive. Defaults to `info` if unset.
    #[arg(long, env = "RUST_LOG")]
    log: Option<String>,

    /// Enable SolidOS mashlib data browser.  When a browser navigates
    /// to an RDF resource (`Accept: text/html`), the server returns an
    /// HTML wrapper that loads mashlib and renders the data client-side.
    #[arg(long, env = "JSS_MASHLIB")]
    mashlib: bool,

    /// Mashlib CDN version (e.g. `2.0.0`).  Ignored when
    /// `--mashlib-module` is set.
    #[arg(long, env = "JSS_MASHLIB_CDN", default_value = "2.0.0")]
    mashlib_cdn: Option<String>,

    /// Load mashlib from an ES module URL instead of CDN (the LOSOS
    /// pattern).  Implies `--mashlib`.
    #[arg(long, env = "JSS_MASHLIB_MODULE")]
    mashlib_module: Option<String>,

    /// Inject a WebSocket reload client into served HTML. Development only.
    #[arg(long, env = "JSS_LIVE_RELOAD")]
    live_reload: bool,

    /// Optional TLS key PEM path. When set together with
    /// `--ssl-cert`, the server binds via rustls on the chosen port.
    #[cfg(feature = "tls")]
    #[arg(long, env = "JSS_SSL_KEY")]
    ssl_key: Option<String>,

    /// Optional TLS certificate PEM path.
    #[cfg(feature = "tls")]
    #[arg(long, env = "JSS_SSL_CERT")]
    ssl_cert: Option<String>,

    /// Comma-separated list of allowed CORS origins. When set, only
    /// requests from these origins receive `Access-Control-Allow-Origin`.
    /// When unset or empty, any origin is reflected (local dev default).
    ///
    /// Example: `--allowed-origins https://dreamlab-ai.com,https://staging.dreamlab-ai.com`
    #[arg(long, env = "SOLID_ALLOWED_ORIGINS", value_delimiter = ',')]
    allowed_origins: Vec<String>,

    /// Pre-shared key that protects `POST /_admin/provision/{pubkey}`.
    /// Must be supplied via `X-Pod-Admin-Key` header. When unset, the
    /// endpoint unconditionally returns 403.
    #[arg(long, env = "SOLID_ADMIN_KEY")]
    admin_key: Option<String>,

    /// Allow unauthenticated pod registration through `POST /.pods` and
    /// `POST /api/accounts/new`. Registration is closed by default; the
    /// admin PSK remains available as an explicit per-request override.
    #[arg(long, env = "JSS_OPEN_REGISTRATION")]
    open_registration: bool,

    /// Enable the MCP (Model Context Protocol) server at `POST /mcp`,
    /// exposing the pod as a tool surface for agents (JSS #490). OFF by
    /// default: agent-driven writes plus on-disk keys are an opt-in
    /// security tradeoff. A `JSS_MCP=1` environment value can be
    /// overridden on the command line with `--no-mcp`.
    #[arg(long, env = "JSS_MCP")]
    mcp: bool,

    /// Disable the MCP server even when `--mcp` or `JSS_MCP` is set.
    /// `--no-mcp` always wins.
    #[arg(long)]
    no_mcp: bool,

    /// Do not serve `GET /.notifications` (the `solid-0.1` WebSocket) and do
    /// not advertise it with `Updates-Via` or in `/.well-known/solid`. On by
    /// default; the route and its advertisement always change together.
    #[arg(long, env = "JSS_NO_NOTIFICATIONS")]
    no_notifications: bool,

    /// Mount the embedded Nostr relay (NIP-01/11/16) on the pod server. OFF by
    /// default: it is a public, open relay. WebSocket at `--nostr-path`,
    /// NIP-11 information at the same URL with `Accept: application/nostr+json`.
    #[arg(long, env = "JSS_NOSTR")]
    nostr: bool,

    /// Where the relay is mounted (JSS `--nostr-path`). Only this exact path
    /// and `<path>/info` belong to the relay; everything else stays a pod path.
    #[arg(long, env = "JSS_NOSTR_PATH", default_value = "/relay")]
    nostr_path: String,

    /// Most events the relay keeps in memory (JSS `--nostr-max-events`).
    #[arg(long, env = "JSS_NOSTR_MAX_EVENTS", default_value_t = 1000)]
    nostr_max_events: usize,

    /// Where a container's ACL document lives: `sidecar` (default: the
    /// sibling `<container>.acl`, as before), `inner` (`<container>/.acl`, the
    /// reference JavaScript server's layout) or `both` (sidecar first, inner
    /// only when the sidecar is absent). `inner` drops every sidecar ACL and
    /// widens access to the parent's grant. `inner` and `both` also honour
    /// every inner `<container>/.acl` file, and early releases let an agent
    /// create one without `acl:Control`: review `--acl-layout-report` before
    /// opting in. `both` is the upgrade path for a root holding either form.
    #[arg(long, env = "JSS_ACL_LAYOUT", default_value = "sidecar")]
    acl_layout: String,

    /// Print a read-only review of every container ACL under the filesystem
    /// data root and exit: inner files, both forms and whether they differ,
    /// sidecar-only containers, directories sitting at an ACL key (their
    /// subtrees now inherit the parent's ACL), symlinked ACL files (not
    /// followed; the server reads a relative link inside the data root and
    /// refuses an absolute or outside one) and any read error. Exits non-zero
    /// if anything could not be read. Review it before choosing `inner` or
    /// `both`, which honour inner ACL files that early releases let agents
    /// create without Control. Changes nothing.
    #[arg(long)]
    acl_layout_report: bool,

    /// Content negotiation: accept and advertise `text/n3` request bodies
    /// (JSS `--conneg`, `JSS_CONNEG`).
    #[arg(long, env = "JSS_CONNEG")]
    conneg: bool,

    /// Trust `X-Forwarded-Proto` / `cf-visitor` for the request scheme and
    /// `X-Forwarded-Host` / `Forwarded` for the request host.
    /// Enable only behind a reverse proxy that overwrites those headers;
    /// otherwise a client could forge the NIP-98 URL scheme.
    #[arg(long, env = "JSS_TRUST_PROXY")]
    trust_proxy: bool,

    /// Public base URL of this server, e.g. `https://pod.example`. It
    /// becomes the origin for NIP-98 URL matching and every generated
    /// absolute URL, so a forged `Host` / `X-Forwarded-Host` cannot retarget
    /// them. Strongly recommended for any internet-facing deployment.
    #[arg(long, env = "JSS_PUBLIC_BASE_URL")]
    public_base_url: Option<String>,

    /// Hosts this server answers for (`host` or `host:port`, comma
    /// separated). A request for any other `Host` gets `421`. Empty allows
    /// any host.
    #[arg(long, env = "JSS_ALLOWED_HOSTS", value_delimiter = ',')]
    allowed_hosts: Vec<String>,

    /// Origins whose `/.well-known/did/nostr/<pk>.json` may link a Nostr key
    /// to a WebID (needs the `did-nostr` feature). Comma separated.
    #[arg(long, env = "JSS_DID_NOSTR_ORIGINS", value_delimiter = ',')]
    did_nostr_origins: Vec<String>,

    /// Enable ActivityPub federation (JSS `--activitypub`). Needs the
    /// `activitypub` feature.
    #[arg(long, env = "JSS_ACTIVITYPUB")]
    activitypub: bool,

    /// Mount the ActivityPub federation routes: inbox, outbox, followers and
    /// following collections, and signed delivery (SP-PAR-281). Off by
    /// default and separate from `--activitypub`, which alone serves only the
    /// actor document. Needs `--activitypub` and `--public-base-url` (every
    /// id the server mints comes from it, never from a request's `Host`).
    /// Inbound requests must be HTTP-signed; the outbox takes the pod owner
    /// only; outbound fetches refuse non-public addresses.
    #[arg(long, env = "JSS_AP_FEDERATION")]
    ap_federation: bool,

    /// Serve remoteStorage (draft-dejong-remotestorage-22) at
    /// `/storage/<user>/` over the pod subtree `/remotestorage/`, authorised
    /// only by scoped bearer tokens the pod owner mints at
    /// `POST /remotestorage/tokens`. Off by default.
    #[arg(long, env = "JSS_REMOTESTORAGE")]
    remotestorage: bool,

    /// The remoteStorage user name in `/storage/<user>/` (default: me).
    #[arg(long, env = "JSS_REMOTESTORAGE_USER", default_value = "me")]
    remotestorage_user: String,

    /// Mount the WebRTC signalling relay (SP-PAR-282): a bounded WebSocket
    /// relay of offers, answers and ICE candidates between authenticated
    /// peers, with no access to pod storage. Off by default.
    #[arg(long, env = "JSS_WEBRTC")]
    webrtc: bool,

    /// Where the signalling relay is mounted (default `/webrtc`).
    #[arg(long, env = "JSS_WEBRTC_PATH", default_value = "/webrtc")]
    webrtc_path: String,

    /// Most followers one remote host (by hostname, any port) may have
    /// (default 50). A further new follower from that host is refused.
    #[arg(long, env = "JSS_AP_MAX_FOLLOWERS_PER_HOST")]
    ap_max_followers_per_host: Option<i64>,

    /// ActivityPub username (default: me).
    #[arg(long, env = "JSS_AP_USERNAME")]
    ap_username: Option<String>,

    /// ActivityPub display name (default: the username, else Anonymous).
    #[arg(long, env = "JSS_AP_DISPLAY_NAME")]
    ap_display_name: Option<String>,

    /// ActivityPub bio/summary.
    #[arg(long, env = "JSS_AP_SUMMARY")]
    ap_summary: Option<String>,

    /// Nostr pubkey (64 hex) linked as `alsoKnownAs did:nostr:<pk>`.
    #[arg(long, env = "JSS_AP_NOSTR_PUBKEY")]
    ap_nostr_pubkey: Option<String>,

    /// Operator subcommands (Sprint 11): `quota reconcile`,
    /// `account delete`, `invite create`. When absent the binary runs
    /// the HTTP server (default / existing behaviour).
    #[command(subcommand)]
    op: Option<OperatorCommand>,
}

// ---------------------------------------------------------------------------
// Storage construction
// ---------------------------------------------------------------------------

async fn build_storage(cfg: &StorageBackendConfig) -> anyhow::Result<Arc<dyn Storage>> {
    match cfg {
        StorageBackendConfig::Fs { root } => {
            info!(backend = "fs", root = %root, "initialising storage");
            let fs = FsBackend::new(root.as_str())
                .await
                .with_context(|| format!("initialise FS backend at {root}"))?;
            Ok(Arc::new(fs))
        }
        StorageBackendConfig::Memory => {
            info!(backend = "memory", "initialising storage (ephemeral)");
            Ok(Arc::new(MemoryBackend::new()))
        }
    }
}

fn bind_available(host: &str, requested: u16) -> anyhow::Result<std::net::TcpListener> {
    let attempts = if requested == 0 { 1 } else { 11 };
    for offset in 0..attempts {
        let port = requested.saturating_add(offset);
        match std::net::TcpListener::bind((host, port)) {
            Ok(listener) => {
                listener.set_nonblocking(true)?;
                if offset > 0 {
                    warn!(
                        requested_port = requested,
                        selected_port = port,
                        "port busy; shifted listener"
                    );
                }
                return Ok(listener);
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::AddrInUse && offset + 1 < attempts => {}
            Err(error) => return Err(error).with_context(|| format!("bind {host}:{port}")),
        }
    }
    unreachable!("the final bind attempt always returns")
}

#[cfg(test)]
mod port_tests {
    use super::*;

    #[test]
    fn busy_port_shifts_and_zero_uses_ephemeral_port() {
        let occupied = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let busy = occupied.local_addr().unwrap().port();
        if busy < u16::MAX - 10 {
            let shifted = bind_available("127.0.0.1", busy).unwrap();
            assert!(shifted.local_addr().unwrap().port() > busy);
        }
        let ephemeral = bind_available("127.0.0.1", 0).unwrap();
        assert_ne!(ephemeral.local_addr().unwrap().port(), 0);
    }
}

#[cfg(feature = "tls")]
fn load_rustls_config(cert_path: &str, key_path: &str) -> anyhow::Result<rustls::ServerConfig> {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    let cert_pem =
        std::fs::read(cert_path).with_context(|| format!("open SSL cert {cert_path}"))?;
    let certs: Vec<_> = CertificateDer::pem_slice_iter(&cert_pem)
        .collect::<Result<Vec<_>, _>>()
        .context("parse SSL cert chain")?;
    let key_pem = std::fs::read(key_path).with_context(|| format!("open SSL key {key_path}"))?;
    let key = PrivateKeyDer::from_pem_slice(&key_pem).context("parse SSL private key")?;

    rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("build rustls server config")
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

#[actix_web::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let filter = cli
        .log
        .clone()
        .or_else(|| std::env::var("RUST_LOG").ok())
        .unwrap_or_else(|| "info".to_string());
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(filter))
        .with_target(true)
        .init();

    // Sprint 11: operator subcommand short-circuit — no HTTP server
    // lifecycle for one-shot admin commands.
    if let Some(op) = cli.op {
        return dispatch_operator_cmd(op).await;
    }

    let mut loader = ConfigLoader::new().with_defaults();
    if let Some(path) = cli.config.as_deref() {
        loader = loader.with_file(path);
    }
    let mut cfg: ServerConfig = loader
        .with_env()
        .load()
        .await
        .context("load server config")?;

    if let Some(host) = cli.host.clone() {
        cfg.server.host = host;
    }
    if let Some(port) = cli.port {
        cfg.server.port = port;
    }
    cfg.validate().map_err(anyhow::Error::msg)?;

    if cli.acl_layout_report {
        let StorageBackendConfig::Fs { root } = &cfg.storage else {
            anyhow::bail!("--acl-layout-report needs the filesystem storage backend");
        };
        let findings =
            solid_pod_rs_server::acl_layout_report::scan(std::path::Path::new(root.as_str()));
        print!(
            "{}",
            solid_pod_rs_server::acl_layout_report::render(&findings)
        );
        if solid_pod_rs_server::acl_layout_report::has_errors(&findings) {
            anyhow::bail!("the ACL layout report is incomplete: see the `error` lines above");
        }
        return Ok(());
    }

    let host = cfg.server.host.clone();
    let requested_port = cfg.server.port;
    let listener = bind_available(&host, requested_port)?;
    let port = listener.local_addr()?.port();
    let bind_addr = format!("{host}:{port}");

    // Capture the FS root before moving cfg into storage construction.
    // Used by the `git` feature to locate pod directories on disk.
    let data_root = match &cfg.storage {
        StorageBackendConfig::Fs { root } => Some(std::path::PathBuf::from(root.as_str())),
        _ => None,
    };

    let storage = build_storage(&cfg.storage).await?;
    let base_url = cfg
        .server
        .base_url
        .clone()
        .unwrap_or_else(|| format!("http://{bind_addr}"));

    let mut state = AppState::new(storage);
    state.data_root = data_root;
    state.acl_layout = cli
        .acl_layout
        .parse()
        .map_err(|e: String| anyhow::anyhow!("--acl-layout: {e}"))?;
    if state.acl_layout != solid_pod_rs::wac::AclLayout::Sidecar {
        info!(layout = state.acl_layout.as_str(), "container ACL layout");
    }

    // ADR-2007: record which Bitcoin explorer — and therefore which network —
    // this pod will anchor against, once, at startup. The endpoint is chosen
    // from a single environment variable with a silent testnet4 default, so
    // without this line an operator has no way to tell from the logs whether
    // anchors are being written to the chain they intended.
    solid_pod_rs_server::mempool::log_mempool_selection_once(
        &solid_pod_rs_server::mempool::select_mempool_endpoint(state.mempool_url.as_deref()),
    );
    #[cfg(feature = "quota")]
    if let (Some(root), limit) = (&state.data_root, cfg.security.default_quota_bytes) {
        if limit > 0 {
            state.quota = Some(std::sync::Arc::new(solid_pod_rs::quota::FsQuotaStore::new(
                root.clone(),
                limit,
            )));
            info!(limit_bytes = limit, "per-pod quota enforcement enabled");
        }
    }
    state.allowed_origins = cli.allowed_origins.clone();
    state.admin_key = cli.admin_key.clone();
    // MCP (#490): enabled by --mcp / JSS_MCP, but --no-mcp always wins so a
    // baked-in env value can be overridden at the command line.
    state.mcp_enabled = cli.mcp && !cli.no_mcp;
    if cli.nostr {
        let mount = solid_pod_rs_server::nostr_mount::NostrMount::new(
            &cli.nostr_path,
            cli.nostr_max_events,
        )
        .map_err(|e| anyhow::anyhow!("--nostr-path: {e}"))?;
        info!(
            path = mount.path(),
            max_events = cli.nostr_max_events,
            "Nostr relay mounted"
        );
        state.nostr = Some(mount);
    }
    if cli.webrtc
        && cli.nostr
        && cli.webrtc_path.trim_end_matches('/') == cli.nostr_path.trim_end_matches('/')
    {
        anyhow::bail!("--webrtc-path and --nostr-path must differ");
    }
    if cli.webrtc {
        let mount = solid_pod_rs_server::webrtc_mount::WebRtcMount::new(&cli.webrtc_path)
            .map_err(|e| anyhow::anyhow!("--webrtc-path: {e}"))?;
        info!(path = mount.path(), "WebRTC signalling relay mounted");
        state.webrtc = Some(mount);
    }
    if cli.remotestorage {
        let rs = solid_pod_rs_server::remotestorage::RemoteStorage::new(
            &cli.remotestorage_user,
            state.data_root.as_deref(),
        )
        .map_err(|e| anyhow::anyhow!("--remotestorage-user: {e}"))?;
        info!(
            user = rs.user(),
            "remoteStorage mounted at /storage/<user>/"
        );
        match solid_pod_rs_server::remotestorage::secure_container(
            &*state.storage,
            state.acl_layout,
        )
        .await
        {
            Ok(solid_pod_rs_server::remotestorage::ContainerAcl::Created) => info!(
                "wrote an owner-only ACL for /remotestorage/ (the root ACL no longer governs it)"
            ),
            Ok(solid_pod_rs_server::remotestorage::ContainerAcl::Existing) => {}
            Ok(solid_pod_rs_server::remotestorage::ContainerAcl::ExistingPermissive) => tracing::warn!(
                "the existing ACL for /remotestorage/ grants Read to the public or to authenticated agents: \
                 every stored document is readable over LDP on the pod origin (responses are sandboxed, \
                 but the data is not private)"
            ),
            Ok(solid_pod_rs_server::remotestorage::ContainerAcl::NoOwner) => tracing::warn!(
                "the root ACL names no acl:agent with Control: wrote an ACL with no authorisations for \
                 /remotestorage/ (denied over LDP; tokens still work)"
            ),
            Err(e) => anyhow::bail!("--remotestorage: could not secure /remotestorage/: {e}"),
        }
        state.remotestorage = Some(rs);
    }
    if cli.no_notifications {
        state.notifications = None;
        info!(
            "notifications disabled — /.notifications is not mounted and Updates-Via is not sent"
        );
    }
    if state.mcp_enabled {
        info!("MCP server enabled — POST /mcp is live (agent tool surface, #490)");
    }
    state.nodeinfo = NodeInfoMeta {
        software_name: "solid-pod-rs-server".into(),
        software_version: env!("CARGO_PKG_VERSION").into(),
        open_registrations: cli.open_registration || cfg.extras.invite_only == Some(false),
        total_users: 0,
        base_url,
    };
    // Mashlib configuration — module URL takes priority over CDN version.
    let mashlib_enabled = cli.mashlib || cli.mashlib_module.is_some();
    if mashlib_enabled {
        state.mashlib.enabled = true;
        if let Some(ref module_url) = cli.mashlib_module {
            state.mashlib.mode = solid_pod_rs::MashlibMode::Module {
                url: module_url.clone(),
            };
        } else if let Some(ref version) = cli.mashlib_cdn {
            state.mashlib.mode = solid_pod_rs::MashlibMode::Cdn {
                version: version.clone(),
            };
        }
    }
    state.mashlib_cdn = cli.mashlib_cdn.clone();
    state.live_reload = cli.live_reload;

    state.conneg_enabled = cli.conneg || cfg.extras.conneg_enabled == Some(true);
    state.trust_proxy = cli.trust_proxy || cfg.extras.trust_proxy == Some(true);
    if let Some(raw) = cli.public_base_url.as_deref() {
        match solid_pod_rs_server::scheme::normalise_origin(raw) {
            Some(o) => {
                info!("public origin pinned to {o}");
                state.public_base_url = Some(o);
            }
            None => {
                eprintln!("error: --public-base-url / JSS_PUBLIC_BASE_URL must be an http(s) URL");
                std::process::exit(2);
            }
        }
    }
    state.allowed_hosts = cli
        .allowed_hosts
        .iter()
        .map(|h| h.trim().to_string())
        .filter(|h| !h.is_empty())
        .collect();
    if state.trust_proxy {
        info!("trusting X-Forwarded-Proto / cf-visitor for the request scheme");
    }

    // Row 60: did:nostr to WebID cross-identity for NIP-98 callers. Local
    // profile always; remote DID-document origins only when configured.
    {
        let origins: Vec<String> = if cli.did_nostr_origins.is_empty() {
            cfg.extras.did_nostr_origins.clone()
        } else {
            cli.did_nostr_origins.clone()
        };
        let resolver = solid_pod_rs_server::cross_identity::PodCrossIdentity::new(
            state.storage.clone(),
            state.nodeinfo.base_url.clone(),
        );
        #[cfg(feature = "did-nostr")]
        let resolver = if origins.is_empty() {
            resolver
        } else {
            info!(
                ?origins,
                "did:nostr remote resolution enabled (SSRF policy from env)"
            );
            resolver.with_remote(
                solid_pod_rs::interop::did_nostr::DidNostrResolver::new(Arc::new(
                    solid_pod_rs::security::ssrf::SsrfPolicy::from_env(),
                )),
                origins,
            )
        };
        #[cfg(not(feature = "did-nostr"))]
        if !origins.is_empty() {
            warn!("did-nostr origins configured but the `did-nostr` feature is not compiled in");
        }
        state.cross_identity = Some(Arc::new(resolver));
    }

    let ap_requested = cli.activitypub || cfg.extras.activitypub_enabled == Some(true);
    #[cfg(feature = "activitypub")]
    if ap_requested {
        let (private_pem, pem) =
            solid_pod_rs_server::activitypub::load_or_create_keypair(state.data_root.as_deref())
                .map_err(anyhow::Error::msg)
                .context("ActivityPub keypair")?;
        let pick = |c: &Option<String>, e: &Option<String>| c.clone().or_else(|| e.clone());
        let ap = solid_pod_rs_server::activitypub::ApConfig::from_knobs(
            pick(&cli.ap_username, &cfg.extras.ap_username).as_deref(),
            pick(&cli.ap_display_name, &cfg.extras.ap_display_name).as_deref(),
            pick(&cli.ap_summary, &cfg.extras.ap_summary).as_deref(),
            pick(&cli.ap_nostr_pubkey, &cfg.extras.ap_nostr_pubkey).as_deref(),
            pem,
        )
        .map_err(anyhow::Error::msg)?;
        info!(username = %ap.username, "ActivityPub actor route enabled");
        if cli.ap_federation {
            let Some(origin) = state.public_origin() else {
                anyhow::bail!(
                    "--ap-federation needs --public-base-url (a bare scheme://host): the actor, \
                     key and collection ids are minted from it"
                );
            };
            let store = solid_pod_rs_server::activitypub::open_store(state.data_root.as_deref())
                .await
                .map_err(anyhow::Error::msg)
                .context("ActivityPub store")?;
            let mut limits = solid_pod_rs_activitypub::InboxLimits::default();
            if let Some(n) = cli.ap_max_followers_per_host {
                if n < 1 {
                    anyhow::bail!("--ap-max-followers-per-host must be at least 1");
                }
                limits.max_followers_per_host = n;
            }
            let fed = solid_pod_rs_server::activitypub::Federation::start_with_limits(
                &ap,
                private_pem,
                &origin,
                store,
                solid_pod_rs_activitypub::SsrfGuard::strict(),
                solid_pod_rs_server::activitypub::DELIVERY_TICK,
                limits,
            )
            .map_err(anyhow::Error::msg)?;
            info!(
                actor = fed.actor_id(),
                "ActivityPub federation routes enabled"
            );
            state.set_ap_federation(fed);
        }
        state.activitypub = Some(Arc::new(ap));
    }
    #[cfg(feature = "activitypub")]
    if cli.ap_federation && !ap_requested {
        anyhow::bail!("--ap-federation needs --activitypub");
    }
    #[cfg(not(feature = "activitypub"))]
    if cli.ap_federation {
        anyhow::bail!("--ap-federation needs a build with the `activitypub` cargo feature");
    }
    #[cfg(not(feature = "activitypub"))]
    if ap_requested {
        anyhow::bail!("--activitypub needs a build with the `activitypub` cargo feature");
    }

    if !cfg.auth.oidc_enabled {
        warn!("auth.oidc_enabled=false — DPoP / OIDC routes disabled");
    }

    info!(%bind_addr, "solid-pod-rs-server starting");

    #[cfg(feature = "forge")]
    solid_pod_rs_server::start_forge(&state)
        .context("the forge could not start; refusing to boot")?;

    let state_factory = state.clone();
    let server_builder = HttpServer::new(move || build_app(state_factory.clone()));

    #[cfg(feature = "tls")]
    let server = {
        match (cli.ssl_key.as_deref(), cli.ssl_cert.as_deref()) {
            (Some(key), Some(cert)) => {
                let rustls_cfg = load_rustls_config(cert, key)?;
                server_builder
                    .listen_rustls_0_23(listener, rustls_cfg)
                    .with_context(|| format!("listen_rustls {bind_addr}"))?
            }
            _ => server_builder
                .listen(listener)
                .with_context(|| format!("listen {bind_addr}"))?,
        }
    };

    #[cfg(not(feature = "tls"))]
    let server = server_builder
        .listen(listener)
        .with_context(|| format!("listen {bind_addr}"))?;

    let server = server.shutdown_timeout(30).run();
    let server_handle = server.handle();

    let shutdown = tokio::spawn(async move {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("SIGINT received — initiating graceful shutdown");
            }
            _ = terminate_signal() => {
                info!("SIGTERM received — initiating graceful shutdown");
            }
        }
        server_handle.stop(true).await;
    });

    // The forge mirror's relay sessions are closed on both paths: a server
    // that exits with an error must not leave them to be cut when the runtime
    // drops. The signal task only waits for a signal, so abort rather than
    // await it on the error path.
    let served = server.await.context("HTTP server exited with error");
    if served.is_err() {
        shutdown.abort();
    }
    let _ = shutdown.await;
    #[cfg(feature = "forge")]
    solid_pod_rs_server::stop_forge(&state).await;
    served?;
    info!("solid-pod-rs-server stopped cleanly");
    Ok(())
}

#[cfg(unix)]
async fn terminate_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    if let Ok(mut stream) = signal(SignalKind::terminate()) {
        stream.recv().await;
    } else {
        std::future::pending::<()>().await;
    }
}

#[cfg(not(unix))]
async fn terminate_signal() {
    std::future::pending::<()>().await;
}
