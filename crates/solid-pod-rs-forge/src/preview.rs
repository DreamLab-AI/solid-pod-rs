//! `POST <prefix>/api/repos/<owner>/<repo>/preview`: the **unstaged** tier.
//!
//! Follows the JSS `forge` `apiRepoPreview` and `EPHEMERAL_PREVIEW_KIND`
//! (cited by name only). The endpoint publishes one signed, **ephemeral**
//! Nostr event (kind [`EPHEMERAL_PREVIEW_KIND`], 21617, inside the NIP-01
//! 20000-29999 ephemeral range) that carries the file content, and makes no
//! commit, no ref update and no anchor, and writes nothing to disk. Relays do
//! not store ephemeral events, so only viewers connected at that moment see
//! the preview.
//!
//! Authorisation, body rules, size caps and CORS are exactly those of
//! [`crate::web_edit`]: owner-signed unless
//! [`ForgeConfig::open_edit`](crate::ForgeConfig::open_edit) is on. The event
//! is signed with the forge-instance announce key and sent through the same
//! relay publisher and SSRF policy as the repository announcements; it needs
//! the `announce` feature (without it the endpoint validates and then answers
//! `501`).
//!
//! The event tags are `["d", "<owner>/<repo>"]`, `["f", "<path>"]` and
//! `["branch", "<branch>"]`; the content is the file content as sent.
//!
//! # Examples
//!
//! ```
//! assert_eq!(solid_pod_rs_forge::preview::EPHEMERAL_PREVIEW_KIND, 21617);
//! ```

use crate::ownership::ForgeAgent;
use crate::request::{ForgeRequest, ForgeResponse};
use crate::web_edit::{cors_err, resolve_branch, validate};
use crate::ForgeService;

/// The NIP-01 ephemeral event kind used for previews (JSS
/// `EPHEMERAL_PREVIEW_KIND`).
pub const EPHEMERAL_PREVIEW_KIND: u64 = 21617;

impl ForgeService {
    /// `POST api/repos/<o>/<n>/preview` (JSS `apiRepoPreview`). Never returns
    /// an error: every outcome is a CORS-readable JSON reply.
    pub(crate) async fn h_api_preview(
        &self,
        req: &ForgeRequest,
        agent: &ForgeAgent,
        owner: &str,
        name: &str,
    ) -> ForgeResponse {
        if !req.method.eq_ignore_ascii_case("POST") {
            return crate::api::api_err(405, "method not allowed");
        }
        let ed = match validate(self.cfg.open_edit, req, agent, owner, "preview") {
            Ok(e) => e,
            Err(resp) => return resp,
        };
        let dir = match self.resolve_repo(owner, name).await {
            Ok(d) => d,
            Err(_) => return cors_err(404, "not found"),
        };
        let branch = match resolve_branch(&dir, ed.branch.as_ref()).await {
            Ok(b) => b,
            Err(resp) => return resp,
        };
        self.publish_preview(owner, name, &branch, &ed).await
    }

    #[cfg(feature = "announce")]
    async fn publish_preview(
        &self,
        owner: &str,
        name: &str,
        branch: &str,
        ed: &crate::web_edit::EditRequest,
    ) -> ForgeResponse {
        use crate::publish::{publish_event, RELAY_TIMEOUT};
        use crate::web_edit::cors_json;
        let a = &self.announcer;
        if a.relays.is_empty() {
            return cors_json(
                200,
                &serde_json::json!({
                    "ok": true,
                    "published": false,
                    "reason": "no relays configured (set config.announceRelays)",
                }),
            );
        }
        let tags = vec![
            vec!["d".to_string(), format!("{owner}/{name}")],
            vec!["f".to_string(), ed.path.clone()],
            vec!["branch".to_string(), branch.to_string()],
        ];
        let ev = match a
            .signer
            .sign(EPHEMERAL_PREVIEW_KIND, tags, &ed.content, crate::now_secs())
        {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!("forge: preview {owner}/{name} signing failed: {e}");
                return cors_err(500, "preview failed");
            }
        };
        let relays = publish_event(&ev, &a.relays, RELAY_TIMEOUT, a.ssrf.as_ref()).await;
        cors_json(
            200,
            &serde_json::json!({
                "ok": true,
                "published": true,
                "kind": ev.kind,
                "id": ev.id,
                "path": ed.path,
                "relays": serde_json::to_value(&relays).unwrap_or(serde_json::Value::Null),
            }),
        )
    }

    #[cfg(not(feature = "announce"))]
    async fn publish_preview(
        &self,
        _owner: &str,
        _name: &str,
        _branch: &str,
        _ed: &crate::web_edit::EditRequest,
    ) -> ForgeResponse {
        cors_err(501, "NIP-34 emission is not compiled into this build")
    }
}
