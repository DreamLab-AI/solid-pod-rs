//! The SSRF allowance for operator-listed relays, shared by the NIP-34
//! publisher (`announce`) and the kind-30618 mirror (`mirror`).
//!
//! A relay the operator names (`FORGE_ANNOUNCE_RELAYS`, `FORGE_MIRROR_RELAYS`)
//! may sit on loopback or a private network (the embedded relay of an agent
//! container); [`OperatorRelays`] admits exactly those `host:port` pairs and
//! sends every other host to the workspace default policy.

use solid_pod_rs_nostr::SsrfCheck;

/// An SSRF policy for operator-configured relays: a host that is exactly one
/// of the relays the operator listed (host and port) is admitted without
/// resolution, which is what lets a loopback or private-network relay (the
/// embedded relay of an agent container) be named; every other host gets the
/// workspace default, so a relay URL taken from anywhere else is still
/// screened.
///
/// # Examples
///
/// ```
/// use solid_pod_rs_forge::operator_relays::OperatorRelays;
/// use solid_pod_rs_nostr::SsrfCheck;
///
/// # let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
/// # rt.block_on(async {
/// let policy = OperatorRelays::new(&["ws://127.0.0.1:7777".to_string()]);
/// assert!(policy.verify_host("127.0.0.1:7777").await.is_ok());
/// assert!(policy.verify_host("127.0.0.1:9999").await.is_err());
/// # });
/// ```
#[derive(Debug, Clone, Default)]
pub struct OperatorRelays {
    allowed: Vec<String>,
}

impl OperatorRelays {
    /// Build the allow-list from relay URLs (`ws://host[:port]/…`); malformed
    /// entries are skipped.
    #[must_use]
    pub fn new(relays: &[String]) -> Self {
        let allowed = relays
            .iter()
            .filter_map(|r| url::Url::parse(r).ok())
            .filter_map(|u| {
                let host = u.host_str()?.to_ascii_lowercase();
                let port = u.port_or_known_default()?;
                Some(format!("{host}:{port}"))
            })
            .collect();
        Self { allowed }
    }
}

#[async_trait::async_trait]
impl SsrfCheck for OperatorRelays {
    async fn verify_host(&self, host: &str) -> Result<Option<std::net::IpAddr>, String> {
        let h = host.to_ascii_lowercase();
        // A bare host means the scheme's default port.
        let bare = (!h.contains(':')).then(|| [format!("{h}:80"), format!("{h}:443")]);
        if self
            .allowed
            .iter()
            .any(|a| *a == h || bare.as_ref().is_some_and(|b| b.contains(a)))
        {
            return Ok(None);
        }
        solid_pod_rs_nostr::DefaultSsrfCheck.verify_host(host).await
    }
}
