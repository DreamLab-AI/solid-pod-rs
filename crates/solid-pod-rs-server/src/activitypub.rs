//! ActivityPub actor endpoint wiring (cargo feature `activitypub`).
//!
//! Mirrors the JSS single-user ActivityPub plugin: `src/ap/index.js` builds a
//! config from `username` / `displayName` / `summary` / `nostrPubkey`
//! (defaults `me` and `Anonymous`, server.js 134-135), and the dedicated
//! `GET /profile/card.jsonld` route in `src/server.js` 545-570 answers an
//! `Accept: application/activity+json` request with the actor document built
//! by `src/ap/routes/actor.js`, delegating everything else to the normal
//! resource handler. A configured Nostr pubkey is linked as
//! `alsoKnownAs: ["did:nostr:<pk>"]` (actor.js 61-64).
//!
//! Operator knobs: `--ap-username`, `--ap-display-name`, `--ap-summary`,
//! `--ap-nostr-pubkey` (env `JSS_AP_*`, config `extras.ap_*`).
//!
//! Divergence from JSS: the summary is HTML-escaped before it is wrapped in
//! `<p>`; JSS interpolates it raw, which lets a misconfigured summary inject
//! markup into every remote timeline that renders the actor.

use std::path::Path;

use solid_pod_rs_activitypub::{generate_actor_keypair, render_actor, with_also_known_as};

/// Fully resolved ActivityPub actor configuration.
#[derive(Debug, Clone)]
pub struct ApConfig {
    /// WebFinger local part and `preferredUsername`.
    pub username: String,
    /// Human-facing `name`.
    pub display_name: String,
    /// Plain-text bio (escaped on output). Empty means none.
    pub summary: String,
    /// Lowercase hex Nostr pubkey linked through `alsoKnownAs`.
    pub nostr_pubkey: Option<String>,
    /// PEM public key published in the actor document.
    pub public_key_pem: String,
}

fn valid_username(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

impl ApConfig {
    /// Build a config from the operator knobs, applying the JSS defaults:
    /// username `me`; display name = display name, else the username as
    /// given, else `Anonymous`.
    ///
    /// Rejects a username outside `[A-Za-z0-9_.-]{1,64}` and a pubkey that
    /// is not 64 hex characters.
    pub fn from_knobs(
        username: Option<&str>,
        display_name: Option<&str>,
        summary: Option<&str>,
        nostr_pubkey: Option<&str>,
        public_key_pem: String,
    ) -> Result<Self, String> {
        fn non_empty(o: Option<&str>) -> Option<&str> {
            o.map(str::trim).filter(|s| !s.is_empty())
        }
        let given_username = non_empty(username);
        if let Some(u) = given_username {
            if !valid_username(u) {
                return Err(format!("invalid ActivityPub username {u:?}"));
            }
        }
        let nostr_pubkey = match non_empty(nostr_pubkey) {
            Some(pk) => {
                let pk = pk.to_ascii_lowercase();
                if !crate::cross_identity::is_hex_pubkey(&pk) {
                    return Err("ActivityPub nostr pubkey must be 64 hex characters".into());
                }
                Some(pk)
            }
            None => None,
        };
        Ok(Self {
            username: given_username.unwrap_or("me").to_string(),
            display_name: non_empty(display_name)
                .or(given_username)
                .unwrap_or("Anonymous")
                .to_string(),
            summary: non_empty(summary).unwrap_or("").to_string(),
            nostr_pubkey,
            public_key_pem,
        })
    }

    /// The actor document for the site at `base_url` (`scheme://host`).
    pub fn actor_json(&self, base_url: &str) -> serde_json::Value {
        let summary = if self.summary.is_empty() {
            String::new()
        } else {
            format!("<p>{}</p>", html_escape(&self.summary))
        };
        let mut actor = render_actor(
            base_url,
            &self.username,
            &self.display_name,
            Some(&summary),
            &self.public_key_pem,
        );
        if let Some(pk) = &self.nostr_pubkey {
            actor = with_also_known_as(actor, [format!("did:nostr:{pk}")]);
        }
        serde_json::to_value(actor).unwrap_or(serde_json::Value::Null)
    }
}

impl crate::ActorDocument for ApConfig {
    fn actor_json(&self, base_url: &str) -> serde_json::Value {
        ApConfig::actor_json(self, base_url)
    }
}

/// Escape the five HTML-significant characters.
pub fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// Load the actor's public key PEM from `<data_root>/.ap/keys.json`, or
/// generate an RSA-2048 pair and persist it there (mode 0600 on Unix).
/// Without a data root the pair lives only for this process. Mirrors JSS
/// `src/ap/keys.js` `loadOrCreateKeypair`, which stores `data/ap-keys.json`.
///
/// Creation is atomic and race-safe (security review L8): the pair is written
/// to a uniquely named 0600 temp file and then published with `hard_link`,
/// which fails rather than replaces if another process got there first, in
/// which case the winner's key is read back. A crash can therefore never leave
/// a half-written `keys.json`, and two processes starting together agree on
/// one key. An empty `keys.json` left by the earlier, non-atomic writer is
/// discarded and regenerated.
pub fn load_or_create_public_key(data_root: Option<&Path>) -> Result<String, String> {
    let file = data_root.map(|r| r.join(".ap").join("keys.json"));
    let Some(f) = &file else {
        return generate_actor_keypair()
            .map(|(_, public)| public)
            .map_err(|e| e.to_string());
    };
    for _ in 0..4 {
        if let Some(public) = read_public_key(f)? {
            return Ok(public);
        }
        let (private_pem, public_pem) = generate_actor_keypair().map_err(|e| e.to_string())?;
        if let Some(dir) = f.parent() {
            std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        }
        let body = serde_json::json!({"publicKey": public_pem, "privateKey": private_pem});
        match publish_private(f, body.to_string().as_bytes()) {
            Ok(()) => return Ok(public_pem),
            // Another process published first: use its key.
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(format!("{}: {e}", f.display())),
        }
    }
    Err(format!("{}: could not settle on a key file", f.display()))
}

/// The stored public key, `None` when the file is absent or empty (a crashed
/// legacy writer; the empty file is removed so it can be recreated).
fn read_public_key(f: &Path) -> Result<Option<String>, String> {
    let text = match std::fs::read_to_string(f) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("{}: {e}", f.display())),
    };
    if text.trim().is_empty() {
        let _ = std::fs::remove_file(f);
        return Ok(None);
    }
    let v: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("{}: {e}", f.display()))?;
    v.get("publicKey")
        .and_then(|p| p.as_str())
        .map(|p| Some(p.to_string()))
        .ok_or_else(|| format!("{}: missing publicKey", f.display()))
}

/// Write `bytes` to a fresh 0600 temp file beside `path`, then link it into
/// place without replacing anything (`AlreadyExists` if `path` is taken).
fn publish_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let tmp = path.with_extension(format!(
        "{}.{}.{nanos}.tmp",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let written = opts.open(&tmp).and_then(|mut f| {
        f.write_all(bytes)?;
        f.sync_all()
    });
    let linked = written.and_then(|()| std::fs::hard_link(&tmp, path));
    let _ = std::fs::remove_file(&tmp);
    linked
}

#[cfg(test)]
mod tests {
    use super::*;

    const PK: &str = "abcd000000000000000000000000000000000000000000000000000000000001";

    #[test]
    fn jss_defaults() {
        let c = ApConfig::from_knobs(None, None, None, None, "PEM".into()).unwrap();
        assert_eq!(c.username, "me");
        assert_eq!(c.display_name, "Anonymous");
        let j = c.actor_json("https://pod.example");
        assert_eq!(j["preferredUsername"], "me");
        assert_eq!(j["name"], "Anonymous");
        assert_eq!(j["summary"], "");
        assert!(j.get("alsoKnownAs").is_none());
        assert_eq!(j["id"], "https://pod.example/profile/card.jsonld#me");
    }

    #[test]
    fn display_name_falls_back_to_given_username() {
        let c = ApConfig::from_knobs(Some("alice"), None, None, None, "P".into()).unwrap();
        assert_eq!(c.display_name, "alice");
    }

    #[test]
    fn nostr_pubkey_links_also_known_as_and_summary_is_escaped() {
        let c = ApConfig::from_knobs(
            Some("alice"),
            Some("Alice"),
            Some("hi <script>x</script> & co"),
            Some(&PK.to_uppercase()),
            "P".into(),
        )
        .unwrap();
        let j = c.actor_json("https://pod.example");
        assert_eq!(j["alsoKnownAs"][0], format!("did:nostr:{PK}"));
        assert_eq!(
            j["summary"],
            "<p>hi &lt;script&gt;x&lt;/script&gt; &amp; co</p>"
        );
    }

    #[test]
    fn bad_knobs_are_rejected() {
        assert!(ApConfig::from_knobs(Some("a b"), None, None, None, "P".into()).is_err());
        assert!(ApConfig::from_knobs(Some("a/../b"), None, None, None, "P".into()).is_err());
        assert!(ApConfig::from_knobs(None, None, None, Some("nothex"), "P".into()).is_err());
    }

    #[test]
    fn keypair_persists_across_loads() {
        let dir = tempfile::tempdir().unwrap();
        let a = load_or_create_public_key(Some(dir.path())).unwrap();
        let b = load_or_create_public_key(Some(dir.path())).unwrap();
        assert_eq!(a, b);
        assert!(a.contains("BEGIN PUBLIC KEY"));
    }

    /// L8: an empty `keys.json` (a crash under the old writer) is replaced
    /// rather than failing every boot.
    #[test]
    fn empty_key_file_is_regenerated() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".ap")).unwrap();
        std::fs::write(dir.path().join(".ap/keys.json"), b"").unwrap();
        let pem = load_or_create_public_key(Some(dir.path())).unwrap();
        assert!(pem.contains("PUBLIC KEY"));
        assert_eq!(load_or_create_public_key(Some(dir.path())).unwrap(), pem);
    }

    /// L8: processes (threads here) starting together settle on one key and
    /// leave no temp files behind.
    #[test]
    fn racing_creators_agree_on_one_key() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let handles: Vec<_> = (0..6)
            .map(|_| {
                let r = root.clone();
                std::thread::spawn(move || load_or_create_public_key(Some(&r)).unwrap())
            })
            .collect();
        let keys: Vec<String> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        assert!(keys.windows(2).all(|w| w[0] == w[1]), "one key for all");
        let names: Vec<_> = std::fs::read_dir(dir.path().join(".ap"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["keys.json".to_string()], "no temp files left");
    }
}
