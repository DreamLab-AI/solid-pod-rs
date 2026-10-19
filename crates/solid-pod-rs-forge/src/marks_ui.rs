//! The Anchors page and its tab (feature `anchoring`).
//!
//! The Rust counterpart of the JSS `forge` plugin's `marksPage`, `chainBadge`
//! and the Anchors entry of the repository tab strip. Three states of one URL,
//! `/<owner>/<repo>/marks`:
//!
//! - **forge-held** ([`forge_held_page`]): the forge derived the marks. Chips,
//!   explorer links, the settled frontier and tip balance, the verifier
//!   hand-off and the fund box.
//! - **repo-held** ([`repo_held_page`]): the repository's own key marks commits
//!   with the `git mark` CLI and commits `blocktrails.json`. The page re-derives
//!   every address and links each mark.
//! - **not enabled** ([`pitch_page`]): the Enable pitch.
//!
//! Like every forge view the page is server-rendered, takes no script and
//! passes every interpolated value through [`esc`]. The Enable and Record
//! controls are plain forms that post to the API; a pod session authenticates
//! them, and NIP-98 agents call the API directly. The tab itself is controlled
//! by [`crate::ForgeConfig::anchoring_ui`]: with it on, every repository shows
//! the tab and the page carries the Enable pitch; with it off, only a
//! repository that already carries a trail does.
//!
//! The forge never broadcasts. Every address on these pages is derived and
//! shown; funding and spending happen on the owner's machine.

use crate::config::chain_hrp;
use crate::gitmark::{explorer_tx_url, RepoTrail};
use crate::html::{crumbs, page};
use crate::request::esc;
use crate::trail::{MarkStatus, Trail};

/// The six lines that take a fresh repository to an announced mark with a
/// repo-held key (shown wherever the page explains how a trail is made).
const SIX_LINES: &str =
    "npm init agent                 # a key in git config nostr.privkey, a did:nostr\n\
npx fund-agent                 # 10,000 sats to that key from your voucher file\n\
git mark init --chain txbt4    # the trail: finds the coin at the key's address\n\
git add . &amp;&amp; git commit -m first\n\
git mark                       # spend the coin to the commit's address = the mark\n\
git mark announce              # NIP-34 kind 30617 with chain, txo and commit tags";

/// The hosted independent verifier, which takes the trail document's URL.
const VERIFIER: &str = "https://blocktrails.github.io/verify/?uri=";

const MARKS_CSS: &str = "<style>\
.chip{font-size:.8rem;padding:.1rem .5rem;border-radius:10px}\
.chip-marked{background:#2c9e4b33;color:#2c9e4b}.chip-pending{background:#c9892033;color:#b57a12}\
.markstats{display:flex;gap:1rem;flex-wrap:wrap;margin:0 0 1rem}\
.mstat{border:1px solid #8884;border-radius:6px;padding:.5rem .8rem;min-width:11rem}\
.mstat .k{font-size:.8rem;color:#8888}.mstat .v{font-size:1.15rem}.mstat .s{font-size:.8rem;color:#8888}\
.unit{font-size:.8rem;color:#8888}\
.fundbox{border:1px solid #8884;border-radius:6px;padding:.75rem 1rem;margin-top:1rem}\
a.btn,button.btn{display:inline-block;border:1px solid #8886;border-radius:6px;padding:.25rem .7rem;\
background:transparent;color:inherit;font:inherit;cursor:pointer}\
.sha{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}\
</style>";

/// What the Anchors page needs to know about where it is rendered.
#[derive(Debug, Clone, Copy)]
pub struct MarksCtx<'a> {
    /// The forge's URL prefix (`/forge`), normalised.
    pub prefix: &'a str,
    /// Owner namespace.
    pub owner: &'a str,
    /// Repository name.
    pub repo: &'a str,
    /// The default branch.
    pub branch: &'a str,
    /// The chain new trails are minted on (shown on the pitch).
    pub chain: &'a str,
    /// Scheme and host of the request (`https://forge.example`), or empty to
    /// render a root-relative trail URL.
    pub origin: &'a str,
}

impl MarksCtx<'_> {
    fn base(&self) -> String {
        format!("{}/{}/{}", self.prefix, self.owner, self.repo)
    }

    fn api(&self) -> String {
        format!("{}/api/repos/{}/{}", self.prefix, self.owner, self.repo)
    }

    fn verify_href(&self) -> String {
        let trail_url = format!("{}{}/blocktrails.json", self.origin, self.base());
        format!("{VERIFIER}{}", uri_component(&trail_url))
    }
}

/// `encodeURIComponent`: every byte but `A-Za-z0-9 - _ . ! ~ * ' ( )` is
/// percent-encoded.
///
/// # Examples
///
/// ```
/// use solid_pod_rs_forge::marks_ui::uri_component;
///
/// assert_eq!(uri_component("/forge/casey/trail/blocktrails.json"),
///            "%2Fforge%2Fcasey%2Ftrail%2Fblocktrails.json");
/// assert_eq!(uri_component("a b&c"), "a%20b%26c");
/// ```
#[must_use]
pub fn uri_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&b) {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Thousands-grouped integer, `250000` to `250,000` (JSS `groupSats`).
///
/// # Examples
///
/// ```
/// use solid_pod_rs_forge::marks_ui::group_sats;
///
/// assert_eq!(group_sats(250_000), "250,000");
/// assert_eq!(group_sats(7), "7");
/// assert_eq!(group_sats(1_234_567_890), "1,234,567,890");
/// ```
#[must_use]
pub fn group_sats(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// The human chain badge (JSS `chainBadge`): `tbtc4` is "testnet4", and a
/// non-mainnet chain carries an honest testnet note.
///
/// # Examples
///
/// ```
/// use solid_pod_rs_forge::marks_ui::chain_badge;
///
/// assert!(chain_badge("tbtc4").contains("testnet4"));
/// assert!(chain_badge("tbtc4").contains("demonstrations, not value"));
/// assert!(!chain_badge("btc").contains("demonstrations"));
/// ```
#[must_use]
pub fn chain_badge(chain: &str) -> String {
    let label = match chain {
        "tbtc4" => "testnet4",
        "tbtc3" => "testnet3",
        other => other,
    };
    let note = if matches!(
        chain.to_ascii_lowercase().as_str(),
        "btc" | "mainnet" | "bitcoin" | "xbt"
    ) {
        ""
    } else {
        " <span class=\"muted\" style=\"font-size:12px\">(testnet: demonstrations, not value)</span>"
    };
    format!("<span class=\"badge\">{}</span>{note}", esc(label))
}

/// The tab strip of a repository page, with the Anchors tab last.
fn tabs(ctx: &MarksCtx<'_>) -> String {
    let b = esc(&ctx.base());
    format!(
        "<nav class=\"crumbs\">\
<a href=\"{b}\">code</a> \u{b7} \
<a href=\"{b}/commits/{r}\">commits</a> \u{b7} \
<a href=\"{b}/branches\">branches</a> \u{b7} \
<a href=\"{b}/tags\">tags</a> \u{b7} \
<a class=\"tab active\" href=\"{b}/marks\">Anchors</a></nav>",
        r = esc(ctx.branch)
    )
}

fn header(ctx: &MarksCtx<'_>) -> String {
    let label = crate::html::agent_label(ctx.owner);
    let mut h = crumbs(&[
        ("forge", Some(ctx.prefix.to_string())),
        (&label, Some(format!("{}/{}", ctx.prefix, ctx.owner))),
        (ctx.repo, Some(ctx.base())),
    ]);
    h.push_str(&format!("<h1>{}/{}</h1>", esc(&label), esc(ctx.repo)));
    h.push_str(&tabs(ctx));
    h
}

/// The exact markup the browse pages end their tab strip with, which the
/// Anchors tab is appended after.
fn tab_slot(prefix: &str, owner: &str, repo: &str) -> String {
    format!(
        "<a href=\"{}/tags\">tags</a></nav>",
        esc(&format!("{prefix}/{owner}/{repo}"))
    )
}

/// Whether `html` is a repository page with a tab strip the Anchors tab can be
/// appended to.
#[must_use]
pub fn has_tab_slot(html: &str, prefix: &str, owner: &str, repo: &str) -> bool {
    html.contains(&tab_slot(prefix, owner, repo))
}

/// Append the Anchors tab to a repository page's tab strip (JSS `repoStrip`
/// with `anchoringUi`). A page without the strip is returned unchanged.
///
/// # Examples
///
/// ```
/// use solid_pod_rs_forge::marks_ui::add_anchors_tab;
///
/// let page = r#"<nav class="crumbs"><a href="/forge/casey/r">code</a> · <a href="/forge/casey/r/tags">tags</a></nav>"#;
/// let out = add_anchors_tab(page, "/forge", "casey", "r");
/// assert!(out.contains(r#"<a class="tab" href="/forge/casey/r/marks">Anchors</a></nav>"#));
/// assert_eq!(add_anchors_tab("<p>none</p>", "/forge", "casey", "r"), "<p>none</p>");
/// ```
#[must_use]
pub fn add_anchors_tab(html: &str, prefix: &str, owner: &str, repo: &str) -> String {
    let slot = tab_slot(prefix, owner, repo);
    let base = esc(&format!("{prefix}/{owner}/{repo}"));
    html.replacen(
        &slot,
        &format!(
            "<a href=\"{base}/tags\">tags</a> \u{b7} <a class=\"tab\" href=\"{base}/marks\">Anchors</a></nav>"
        ),
        1,
    )
}

/// The Enable pitch for a repository with no trail.
#[must_use]
pub fn pitch_page(ctx: &MarksCtx<'_>) -> String {
    let body = format!(
        "{css}{head}<h2>Anchors {badge}</h2>\
<div class=\"fundbox\"><h3>Anchoring is not enabled</h3>\
<p class=\"muted\">Anchor this repository's history to Bitcoin ({chain}) via \
<a href=\"https://blocktrails.org\">Blocktrails</a>: each default-branch tip derives a fresh taproot \
address by BIP-341 TapTweak; spending the previous mark's output to the new address advances a \
tamper-evident, Bitcoin-ordered trail. The forge only <b>derives and records</b>: funding, \
spending and verification all happen off-server.</p>\
<p class=\"muted\">Enabling mints a forge-held trail key ({chain} custody) \
and derives mark&nbsp;0 from the current <b>{branch}</b> tip.</p>\
<p class=\"muted\"><b>Or keep the key in the repo.</b> Mark commits with the git-mark CLI and commit the trail file; \
once <code>{file}</code> is on <b>{branch}</b> this page reads it, re-derives every address and \
links each mark. No forge key, nothing to record:</p>\
<pre>{six}</pre>\
<form method=\"post\" action=\"{api}/marks/enable\">\
<button id=\"do-enable\" class=\"btn\" type=\"submit\">Enable anchoring</button> \
<span class=\"muted\">repository owner only</span></form></div>",
        css = MARKS_CSS,
        head = header(ctx),
        badge = chain_badge(ctx.chain),
        chain = esc(ctx.chain),
        branch = esc(ctx.branch),
        file = esc(crate::gitmark::TRAIL_FILE),
        six = SIX_LINES,
        api = esc(&ctx.api()),
    );
    page(&format!("Anchors \u{b7} {}/{}", ctx.owner, ctx.repo), &body)
}

fn tx_cell(chain: &str, txid: &str, vout: u32) -> String {
    let short = format!("{}\u{2026}", &txid[..txid.len().min(10)]);
    match explorer_tx_url(chain, txid) {
        Some(url) => format!(
            "<a class=\"sha\" href=\"{}\">{}</a>",
            esc(&url),
            esc(&if vout == 0 {
                short
            } else {
                format!("{short}:{vout}")
            })
        ),
        None => format!("<span class=\"sha\">{}</span>", esc(&short)),
    }
}

/// The Anchors page of a forge-held trail (JSS `marksPage`, forge-held branch).
#[must_use]
pub fn forge_held_page(ctx: &MarksCtx<'_>, trail: &Trail) -> String {
    let base = ctx.base();
    let rows: String = trail
        .marks
        .iter()
        .map(|m| {
            let marked = m.status == MarkStatus::Marked;
            format!(
                "<tr><td>#{idx}</td>\
<td><a class=\"sha\" href=\"{base}/commit/{commit}\">{short}</a><div class=\"muted\" style=\"font-size:11px\">{branch}</div></td>\
<td><code>{hash}\u{2026}</code></td>\
<td><code>{addr}</code></td>\
<td><span class=\"chip chip-{cls}\">{cls}</span></td>\
<td>{tx}</td></tr>\n",
                idx = m.index,
                base = esc(&base),
                commit = esc(&m.state.commit),
                short = esc(&m.state.commit[..m.state.commit.len().min(7)]),
                branch = esc(&m.state.branch),
                hash = esc(&m.state_hash[..m.state_hash.len().min(12)]),
                addr = esc(&m.address),
                cls = if marked { "marked" } else { "pending" },
                tx = match (marked, m.txid.as_deref()) {
                    (true, Some(t)) => tx_cell(&trail.chain, t, 0),
                    _ => "<span class=\"muted\">\u{2014}</span>".to_string(),
                },
            )
        })
        .collect();

    let marked = trail.marked_prefix();
    let frontier = marked.last();
    let pending = trail.marks.len() - marked.len();
    let first_pending = trail.marks.iter().find(|m| m.status != MarkStatus::Marked);
    let stats = format!(
        "<div class=\"markstats\">\
<div class=\"mstat\"><div class=\"k\">Settled frontier</div>\n\
<div class=\"v\">{front}</div>\
<div class=\"s\">{front_s}</div></div>\
<div class=\"mstat\"><div class=\"k\">Balance at tip</div>\n\
<div class=\"v\">{bal}</div>\
<div class=\"s\">{bal_s}</div></div>\
<div class=\"mstat\"><div class=\"k\">Pending</div>\n\
<div class=\"v\">{pend}</div>\
<div class=\"s\">{pend_s}</div></div></div>",
        front = frontier.map_or_else(
            || "<span class=\"muted\">none yet</span>".to_string(),
            |f| format!(
                "#{} <a class=\"sha\" href=\"{}/commit/{}\">{}</a>",
                f.index,
                esc(&base),
                esc(&f.state.commit),
                esc(&f.state.commit[..f.state.commit.len().min(7)])
            )
        ),
        front_s = frontier.map_or_else(
            || "genesis not yet funded".to_string(),
            |f| format!("on-chain tip &middot; {}", esc(&f.state.branch))
        ),
        bal = frontier.and_then(|f| f.amount).map_or_else(
            || "<span class=\"muted\">\u{2014}</span>".to_string(),
            |a| format!("{} <span class=\"unit\">sat</span>", group_sats(a))
        ),
        bal_s = if frontier.is_some() {
            format!("live {} output", esc(&trail.chain))
        } else {
            "unfunded".to_string()
        },
        pend = if pending == 0 {
            "settled &#10003;".to_string()
        } else {
            format!(
                "{pending} <span class=\"unit\">mark{}</span>",
                if pending == 1 { "" } else { "s" }
            )
        },
        pend_s = if pending == 0 {
            "trail matches HEAD on-chain"
        } else {
            "ahead of the settled frontier"
        },
    );

    let fund = match first_pending {
        Some(fp)
            if trail
                .marks
                .last()
                .is_some_and(|l| l.status != MarkStatus::Marked) =>
        {
            let step1 = if fp.index == 0 {
                format!(
                    "send {} sats to it from any wallet (a faucet, npx fund-agent's voucher key, your own)",
                    esc(&trail.chain)
                )
            } else {
                "spend the previous mark's output to it (the spend IS the advance)".to_string()
            };
            format!(
                "<div class=\"fundbox\"><h3>Fund this mark <span class=\"chip chip-pending\">pending</span></h3>\
<p class=\"muted\">Mark #{idx} is waiting for its on-chain output. Send {chain} sats to the derived address{how}. \
The forge never broadcasts anything itself.</p>\
<p><code>{addr}</code></p>\
<pre># on YOUR machine: the forge derived the address above and never broadcasts\n\
# 1. {step1}\n\
# 2. record where it landed (repo owner), and the mark turns green: the form below, or:\n\
#    POST {api}/marks/{idx}/txo  {{\"txid\":\"\u{2026}\",\"vout\":0,\"amount\":\u{2026}}}\n\
#\n\
# Prefer the key in the repo? The git-mark CLI (npm gitmark) does the spend, the record\n\
# and the announcement itself; push the trail file and this page reads it:\n\
{six}</pre>\
<form method=\"post\" action=\"{api}/marks/{idx}/txo\">\
<input name=\"txid\" placeholder=\"txid (64 hex)\" size=\"66\"> \
<input name=\"vout\" placeholder=\"vout\" size=\"6\"> \
<input name=\"amount\" placeholder=\"amount (sats)\" size=\"14\"> \
<button id=\"submit-txo\" class=\"btn\" type=\"submit\">Record</button></form></div>",
                idx = fp.index,
                chain = esc(&trail.chain),
                how = if fp.index == 0 {
                    " (the genesis funding)"
                } else {
                    ", by <b>spending the previous mark\u{2019}s output</b>, which IS the advance"
                },
                addr = esc(&fp.address),
                step1 = step1,
                api = esc(&ctx.api()),
                six = SIX_LINES,
            )
        }
        _ => String::new(),
    };

    let body = format!(
        "{css}{head}\
<p><a class=\"btn\" href=\"{base}/blocktrails.json\">blocktrails.json</a> \
<a class=\"btn\" href=\"{verify}\">Verify independently</a></p>\
<h2>Anchors {badge}</h2>\
<p class=\"muted\">Trail key <code>{key}\u{2026}</code> (forge-held, {chain}) &middot; \
{n} mark{s} &middot; the server derives and records; verification runs \
<b>client-side</b> in the hosted verifier against the chain.</p>\
{stats}\
<table class=\"marks\"><tr><th>mark</th><th>commit</th><th>state hash</th><th>derived address</th><th>status</th><th>tx</th></tr>\n{rows}</table>\
{fund}",
        css = MARKS_CSS,
        head = header(ctx),
        base = esc(&base),
        verify = esc(&ctx.verify_href()),
        badge = chain_badge(&trail.chain),
        key = esc(&trail.pubkey_base[..trail.pubkey_base.len().min(10)]),
        chain = esc(&trail.chain),
        n = trail.marks.len(),
        s = if trail.marks.len() == 1 { "" } else { "s" },
    );
    page(&format!("Anchors \u{b7} {}/{}", ctx.owner, ctx.repo), &body)
}

/// The Anchors page of a repo-held git-mark trail (JSS `marksPage`, repo-held
/// branch): read from `blocktrails.json`, every address re-derived, no key and
/// nothing to record.
#[must_use]
pub fn repo_held_page(ctx: &MarksCtx<'_>, rt: &RepoTrail) -> String {
    let base = ctx.base();
    let rows: String = rt
        .marks
        .iter()
        .map(|m| {
            let disagree = match (&m.txo, &m.program) {
                (Some(t), Some(p)) => t
                    .pubkey
                    .as_deref()
                    .is_some_and(|k| !k.eq_ignore_ascii_case(p)),
                _ => false,
            };
            format!(
                "<tr><td>#{idx}</td>\
<td><a class=\"sha\" href=\"{base}/commit/{commit}\">{short}</a></td>\
<td>{addr}{warn}</td><td>{sats}</td><td>{tx}</td></tr>\n",
                idx = m.index,
                base = esc(&base),
                commit = esc(&m.commit),
                short = esc(&m.commit[..m.commit.len().min(7)]),
                addr = m.address.as_deref().map_or_else(
                    || "<span class=\"muted\">unknown chain</span>".to_string(),
                    |a| format!("<code>{}</code>", esc(a))
                ),
                warn = if disagree {
                    "<div class=\"muted\" style=\"font-size:11px\">address in the file disagrees with the derivation</div>"
                } else {
                    ""
                },
                sats = m.txo.as_ref().and_then(|t| t.amount).map_or_else(
                    || "<span class=\"muted\">\u{2014}</span>".to_string(),
                    |a| format!("{a} <span class=\"muted\">sat</span>")
                ),
                tx = m.txo.as_ref().map_or_else(
                    || "<span class=\"muted\">\u{2014}</span>".to_string(),
                    |t| tx_cell(&rt.chain, &t.txid, t.vout)
                ),
            )
        })
        .collect();
    let xonly = rt.xonly();
    let base_addr = chain_hrp(&rt.chain).and_then(|hrp| {
        let prog: [u8; 32] = hex::decode(&xonly).ok()?.try_into().ok()?;
        let hrp = bech32::Hrp::parse(hrp).ok()?;
        bech32::segwit::encode_v1(hrp, &prog).ok()
    });
    let body = format!(
        "{css}{head}\
<p><a class=\"btn\" href=\"{base}/blocktrails.json\">blocktrails.json</a> \
<a class=\"btn\" href=\"{verify}\">Verify independently</a></p>\
<h2>Anchors {badge}</h2>\
<p class=\"muted\">Trail key <code>{key}\u{2026}</code> (<b>repo-held</b>, {chain}) &middot; \
did:nostr:<code>{key}\u{2026}</code> &middot; {n} mark{s} &middot; \
read from <code>{file}</code> at <b>{branch}</b>; every address below is re-derived here from the base key \
and the commits, and verification runs <b>client-side</b> in the hosted verifier against the chain.</p>\
{base_addr}\
<table class=\"marks\"><tr><th>mark</th><th>commit</th><th>derived address</th><th>sats</th><th>tx</th></tr>\n{rows}</table>\
<div class=\"fundbox\"><h3>Next mark</h3>\
<p class=\"muted\">The key never leaves the repo's machine. Each new commit is one <code>git mark</code> \
(300 sats from the trail coin) and one <code>git mark announce</code>; a push brings the updated trail file here.</p>\
<pre>{six}</pre></div>",
        css = MARKS_CSS,
        head = header(ctx),
        base = esc(&base),
        verify = esc(&ctx.verify_href()),
        badge = chain_badge(&rt.chain),
        key = esc(&xonly[..xonly.len().min(10)]),
        chain = esc(&rt.chain),
        n = rt.marks.len(),
        s = if rt.marks.len() == 1 { "" } else { "s" },
        file = esc(crate::gitmark::TRAIL_FILE),
        branch = esc(&rt.branch),
        base_addr = base_addr.map_or_else(String::new, |a| format!(
            "<p class=\"muted\">Base address <code>{}</code>: where <code>npx fund-agent</code> put the first coin.</p>",
            esc(&a)
        )),
        six = SIX_LINES,
    );
    page(&format!("Anchors \u{b7} {}/{}", ctx.owner, ctx.repo), &body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trail::{Mark, MarkState};

    fn ctx<'a>() -> MarksCtx<'a> {
        MarksCtx {
            prefix: "/forge",
            owner: "casey",
            repo: "trail",
            branch: "main",
            chain: "tbtc4",
            origin: "https://forge.example",
        }
    }

    fn mark(i: usize, c: char, marked: bool) -> Mark {
        Mark {
            index: i,
            state: MarkState {
                commit: c.to_string().repeat(40),
                repo: "casey/trail".into(),
                branch: "main".into(),
            },
            state_hash: "ab".repeat(32),
            program: "cd".repeat(32),
            address: format!("tb1pfakeaddress{i}"),
            status: if marked {
                MarkStatus::Marked
            } else {
                MarkStatus::Pending
            },
            at: 1,
            txid: marked.then(|| "e".repeat(64)),
            vout: marked.then_some(0),
            amount: marked.then_some(250_000),
            marked_at: marked.then_some(2),
        }
    }

    fn trail(marks: Vec<Mark>) -> Trail {
        serde_json::from_value(serde_json::json!({
            "v": 1, "chain": "tbtc4", "privkey": "11".repeat(32),
            "pubkeyBase": format!("02{}", "ab".repeat(32)), "createdAt": 1, "marks": marks,
        }))
        .unwrap()
    }

    #[test]
    fn marks_page_renders_chips_links_handoff_and_fund_box() {
        // Transcribed from forge/test.js 'the marks page renders chips, mempool
        // links, the verifier hand-off and the fund box'.
        let t = trail(vec![
            mark(0, 'a', true),
            mark(1, 'b', false),
            mark(2, 'c', false),
        ]);
        let html = forge_held_page(&ctx(), &t);
        assert!(html.contains("chip-marked"), "green marked chip");
        assert!(html.contains("chip-pending"), "amber pending chip");
        assert!(
            html.contains(&format!(
                "https://mempool.space/testnet4/tx/{}",
                "e".repeat(64)
            )),
            "txid links to the testnet4 explorer"
        );
        assert!(html.contains("https://blocktrails.github.io/verify/?uri="));
        assert!(html.contains(&uri_component("/forge/casey/trail/blocktrails.json")));
        assert!(html.contains("testnet4"), "chain badge");
        assert!(html.contains("npx fund-agent"));
        assert!(html.contains("git mark announce"));
        assert!(!html.contains("git-seal"));
        assert!(
            html.contains("tb1pfakeaddress1"),
            "the first PENDING mark is the one to fund"
        );
        assert!(
            !html.contains("tb1pfakeaddress2</code></p>"),
            "not the later one"
        );
        assert!(html.contains("id=\"submit-txo\""));
        assert!(html.contains("/forge/api/repos/casey/trail/marks/1/txo"));
        assert!(!html.contains(&"11".repeat(32)));
    }

    #[test]
    fn marks_page_summarises_frontier_balance_and_pending() {
        // Transcribed from forge/test.js 'the marks page summarises the settled
        // frontier, tip balance and pending count'.
        let t = trail(vec![
            mark(0, 'a', true),
            mark(1, 'b', false),
            mark(2, 'c', false),
        ]);
        let html = forge_held_page(&ctx(), &t);
        assert!(html.contains("Settled frontier"));
        assert!(html.contains("Balance at tip"));
        let at = html.find("Settled frontier</div>").unwrap();
        let tail = &html[at..];
        assert!(
            tail.contains("<div class=\"v\">#0 <a class=\"sha\" href=\"/forge/casey/trail/commit/"),
            "frontier reads as mark #0 with its commit link"
        );
        assert!(html.contains("250,000 <span class=\"unit\">sat</span>"));
        assert!(html.contains("2 <span class=\"unit\">marks</span>"));
    }

    #[test]
    fn settled_trail_has_no_fund_box() {
        let t = trail(vec![mark(0, 'a', true)]);
        let html = forge_held_page(&ctx(), &t);
        assert!(html.contains("settled &#10003;"));
        assert!(!html.contains("Fund this mark"));
        let fresh = trail(vec![mark(0, 'a', false)]);
        let html = forge_held_page(&ctx(), &fresh);
        assert!(html.contains("none yet"));
        assert!(html.contains("genesis not yet funded"));
        assert!(html.contains("(the genesis funding)"));
    }

    #[test]
    fn pitch_has_the_enable_button_and_no_key() {
        // 'a not-enabled repo's marks page is the Enable pitch'
        let html = pitch_page(&ctx());
        assert!(html.contains("id=\"do-enable\""));
        assert!(html.contains("Anchoring is not enabled"));
        assert!(html.contains("action=\"/forge/api/repos/casey/trail/marks/enable\""));
        assert!(html.contains("method=\"post\""));
        assert!(html.contains("git mark announce"));
    }

    #[test]
    fn page_escapes_hostile_names() {
        let c = MarksCtx {
            owner: "<script>x</script>",
            repo: "a\"b",
            branch: "m<ain",
            ..ctx()
        };
        for html in [
            pitch_page(&c),
            forge_held_page(&c, &trail(vec![mark(0, 'a', false)])),
        ] {
            assert!(!html.contains("<script>x"), "owner escaped");
            assert!(!html.contains("m<ain"), "branch escaped");
        }
    }

    #[test]
    fn tab_is_added_after_tags_and_only_once() {
        let strip = "<nav class=\"crumbs\"><a href=\"/forge/casey/r\">code</a> \u{b7} \
<a href=\"/forge/casey/r/tags\">tags</a></nav><p>/forge/casey/r/tags</p>";
        assert!(has_tab_slot(strip, "/forge", "casey", "r"));
        assert!(!has_tab_slot(strip, "/forge", "casey", "other"));
        let out = add_anchors_tab(strip, "/forge", "casey", "r");
        assert!(out.contains("<a class=\"tab\" href=\"/forge/casey/r/marks\">Anchors</a></nav>"));
        assert_eq!(out.matches("Anchors").count(), 1);
        // transcribed regex from 'shows the Anchors tab on a repo that has NOT enabled anchoring'
        assert!(out.contains("class=\"tab\" href=\"/forge/casey/r/marks\">Anchors</a>"));
    }

    #[test]
    fn badge_and_helpers() {
        assert!(chain_badge("tbtc3").contains("testnet3"));
        assert!(chain_badge("xbt").contains("xbt"));
        assert!(!chain_badge("xbt").contains("testnet:"));
        assert_eq!(group_sats(0), "0");
        assert_eq!(group_sats(999), "999");
        assert_eq!(group_sats(1000), "1,000");
        assert_eq!(uri_component("a-b_c.d~e!f*g'h(i)"), "a-b_c.d~e!f*g'h(i)");
        assert_eq!(uri_component("é"), "%C3%A9");
    }
}
