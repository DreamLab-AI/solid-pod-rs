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

    /// Optional mashlib CDN URL. When set the server redirects `/` and
    /// the mashlib asset paths to the CDN. Default bakes the
    /// `unpkg.com/mashlib@2.0.0/dist` path for compatibility with JSS.
    #[arg(long, env = "JSS_MASHLIB_CDN")]
    mashlib_cdn: Option<String>,

    /// Optional TLS key PEM path. When set together with
    /// `--ssl-cert`, the server binds via rustls on the chosen port.
    #[cfg(feature = "tls")]
    #[arg(long, env = "JSS_SSL_KEY")]
    ssl_key: Option<String>,

    /// Optional TLS certificate PEM path.
    #[cfg(feature = "tls")]
    #[arg(long, env = "JSS_SSL_CERT")]
    ssl_cert: Option<String>,

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
        StorageBackendConfig::S3 { bucket, region, .. } => {
            anyhow::bail!(
                "storage.type=s3 requested (bucket={bucket}, region={region}) but this \
                 binary was built without the `s3-backend` feature. Rebuild with \
                 `--features solid-pod-rs/s3-backend` or use fs/memory storage."
            );
        }
    }
}

#[cfg(feature = "tls")]
fn load_rustls_config(
    cert_path: &str,
    key_path: &str,
) -> anyhow::Result<rustls::ServerConfig> {
    use std::fs::File;
    use std::io::BufReader;

    let cert_file = File::open(cert_path)
        .with_context(|| format!("open SSL cert {cert_path}"))?;
    let mut cert_reader = BufReader::new(cert_file);
    let certs: Vec<_> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .context("parse SSL cert chain")?;

    let key_file = File::open(key_path)
        .with_context(|| format!("open SSL key {key_path}"))?;
    let mut key_reader = BufReader::new(key_file);
    let key = rustls_pemfile::private_key(&mut key_reader)
        .context("parse SSL private key")?
        .ok_or_else(|| anyhow::anyhow!("no private key found in {key_path}"))?;

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

    let host = cfg.server.host.clone();
    let port = cfg.server.port;
    let bind_addr = format!("{host}:{port}");

    let storage = build_storage(&cfg.storage).await?;
    let base_url = cfg
        .server
        .base_url
        .clone()
        .unwrap_or_else(|| format!("http://{bind_addr}"));

    let mut state = AppState::new(storage);
    state.nodeinfo = NodeInfoMeta {
        software_name: "solid-pod-rs-server".into(),
        software_version: env!("CARGO_PKG_VERSION").into(),
        open_registrations: false,
        total_users: 0,
        base_url,
    };
    state.mashlib_cdn = cli
        .mashlib_cdn
        .clone()
        .or_else(|| std::env::var("JSS_MASHLIB_CDN").ok());

    if !cfg.auth.oidc_enabled {
        warn!("auth.oidc_enabled=false — DPoP / OIDC routes disabled");
    }

    info!(%bind_addr, "solid-pod-rs-server starting");

    let state_factory = state.clone();
    let server_builder = HttpServer::new(move || build_app(state_factory.clone()));

    #[cfg(feature = "tls")]
    let server = {
        match (cli.ssl_key.as_deref(), cli.ssl_cert.as_deref()) {
            (Some(key), Some(cert)) => {
                let rustls_cfg = load_rustls_config(cert, key)?;
                server_builder
                    .bind_rustls_0_23(&bind_addr, rustls_cfg)
                    .with_context(|| format!("bind_rustls {bind_addr}"))?
            }
            _ => server_builder
                .bind(&bind_addr)
                .with_context(|| format!("bind {bind_addr}"))?,
        }
    };

    #[cfg(not(feature = "tls"))]
    let server = server_builder
        .bind(&bind_addr)
        .with_context(|| format!("bind {bind_addr}"))?;

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

    server.await.context("HTTP server exited with error")?;
    let _ = shutdown.await;
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
