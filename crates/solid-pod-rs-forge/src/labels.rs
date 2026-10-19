//! Issue (and pull request) labels: GitHub's default set, owner-only CRUD,
//! per-item assignment, list filtering, rename / delete cascades and the
//! luminance-aware chip helpers.
//!
//! Follows the JSS `forge` behaviour (`labelDefs`, `ensureLabels`,
//! `resolveLabels`, `apiLabel*`, `apiItemLabels`, `labelTextColor`,
//! `labelChips`), cited by name only. The per-repo label **set** lives in the
//! issue index file ([`crate::spine::issues::IssueIndex::labels`]); the
//! defaults apply until the first label write materialises them. Items store
//! label **names**, so a recolour needs no cascade; rename and delete cascade
//! over issues *and* pulls.
//!
//! # Reuse by pull requests
//!
//! Pull requests keep their own index (`pulls/<owner>/<repo>.json`, kind
//! [`PULLS_KIND`]) whose items carry a `labels` name array. The cascade and the
//! `PUT …/labels` handler therefore work on that file as raw JSON, with no
//! dependency on a pull-request type: a pull-request route only has to call
//! [`ForgeService::put_item_labels`] with [`ItemKind::Pull`], and the label
//! CRUD routes already keep pull labels consistent. Pull writes take
//! [`crate::locks::ForgeLocks::pulls`] **after** the issue lock.

use serde_json::{json, Value};

use crate::api::{api_err, json_resp, read_json_body, unauthorised};
use crate::error::ForgeError;
use crate::ownership::ForgeAgent;
use crate::request::{ForgeRequest, ForgeResponse};
use crate::spine::issues::{load_issue_index, save_issue_index, IssueIndex, Label};
use crate::ForgeService;

/// Spine kind of the pull-request index.
pub const PULLS_KIND: &str = "pulls";
/// Most labels one item may carry.
pub const LABELS_PER_ITEM: usize = 20;

/// GitHub's default label set, in JSS order.
pub const DEFAULT_LABELS: [(&str, &str); 5] = [
    ("bug", "d73a4a"),
    ("enhancement", "a2eeef"),
    ("documentation", "0075ca"),
    ("question", "d876e3"),
    ("wontfix", "ffffff"),
];

/// Which index an item label operation targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ItemKind {
    /// An issue (typed spine).
    Issue,
    /// A pull request (raw JSON spine, see the module docs).
    Pull,
}

/// The default set as [`Label`]s.
///
/// # Examples
///
/// ```
/// let d = solid_pod_rs_forge::labels::default_labels();
/// assert_eq!(d[0].name, "bug");
/// assert_eq!(d[0].color, "d73a4a");
/// assert_eq!(d.len(), 5);
/// ```
#[must_use]
pub fn default_labels() -> Vec<Label> {
    DEFAULT_LABELS
        .iter()
        .map(|(n, c)| Label {
            name: (*n).to_string(),
            color: (*c).to_string(),
        })
        .collect()
}

/// 1 to 50 characters, none of them control characters.
///
/// # Examples
///
/// ```
/// use solid_pod_rs_forge::labels::valid_label_name;
/// assert!(valid_label_name("needs triage"));
/// assert!(!valid_label_name(""));
/// assert!(!valid_label_name(&"x".repeat(51)));
/// assert!(!valid_label_name("a\nb"));
/// ```
#[must_use]
pub fn valid_label_name(s: &str) -> bool {
    let n = s.chars().count();
    (1..=50).contains(&n) && !s.chars().any(|c| c.is_control())
}

/// Exactly six hex digits.
///
/// # Examples
///
/// ```
/// use solid_pod_rs_forge::labels::valid_label_color;
/// assert!(valid_label_color("00FF00"));
/// assert!(!valid_label_color("red"));
/// assert!(!valid_label_color("#00ff00"));
/// ```
#[must_use]
pub fn valid_label_color(s: &str) -> bool {
    s.len() == 6 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// The effective label set: the materialised one, or the defaults.
#[must_use]
pub fn effective_labels(idx: &IssueIndex) -> Vec<Label> {
    idx.labels.clone().unwrap_or_else(default_labels)
}

/// First label **write** materialises the defaults into the index.
pub fn ensure_labels(idx: &mut IssueIndex) -> &mut Vec<Label> {
    idx.labels.get_or_insert_with(default_labels)
}

/// Item label names to `{name, color}` against `defs`; a name with no
/// definition keeps the neutral `ededed`.
///
/// # Examples
///
/// ```
/// use solid_pod_rs_forge::labels::{default_labels, resolve_labels};
/// let r = resolve_labels(&["bug".into(), "gone".into()], &default_labels());
/// assert_eq!(r[0].color, "d73a4a");
/// assert_eq!(r[1].color, "ededed");
/// ```
#[must_use]
pub fn resolve_labels(names: &[String], defs: &[Label]) -> Vec<Label> {
    names
        .iter()
        .map(|n| {
            defs.iter()
                .find(|d| &d.name == n)
                .cloned()
                .unwrap_or(Label {
                    name: n.clone(),
                    color: "ededed".into(),
                })
        })
        .collect()
}

/// Perceptual-luminance text colour for a chip (GitHub style): dark text on
/// bright backgrounds, white on dark ones. `hex` must be six hex digits.
///
/// # Examples
///
/// ```
/// use solid_pod_rs_forge::labels::text_color;
/// assert_eq!(text_color("d73a4a"), "#ffffff");
/// assert_eq!(text_color("00ff00"), "#1f2328");
/// ```
#[must_use]
pub fn text_color(hex: &str) -> &'static str {
    let c = |i: usize| u32::from_str_radix(hex.get(i..i + 2).unwrap_or("00"), 16).unwrap_or(0);
    let lum = 0.299 * f64::from(c(0)) + 0.587 * f64::from(c(2)) + 0.114 * f64::from(c(4));
    if lum > 140.0 {
        "#1f2328"
    } else {
        "#ffffff"
    }
}

/// Rounded chips for resolved labels (everything escaped; the colour is
/// re-validated so a corrupt index cannot inject into the style attribute).
#[must_use]
pub fn chips_html(labels: &[Label]) -> String {
    labels
        .iter()
        .map(|l| {
            let color = if valid_label_color(&l.color) {
                l.color.as_str()
            } else {
                "ededed"
            };
            format!(
                "<span class=\"label-chip\" style=\"background:#{};color:{}\">{}</span>",
                color,
                text_color(color),
                crate::request::esc(&l.name)
            )
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Rename `old` to `new` in a name list; true when something changed.
pub fn rename_in(names: &mut [String], old: &str, new: &str) -> bool {
    let mut touched = false;
    for n in names.iter_mut() {
        if n == old {
            *n = new.to_string();
            touched = true;
        }
    }
    touched
}

/// Drop `name` from a name list; true when something changed.
pub fn remove_from(names: &mut Vec<String>, name: &str) -> bool {
    let before = names.len();
    names.retain(|n| n != name);
    names.len() != before
}

fn names_of(item: &Value) -> Vec<String> {
    item.get("labels")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn set_names(item: &mut Value, names: &[String]) {
    item["labels"] = json!(names);
}

impl ForgeService {
    /// The repo's effective label set.
    ///
    /// # Errors
    ///
    /// A corrupt issue index is a backend error.
    pub async fn label_defs(&self, owner: &str, repo: &str) -> Result<Vec<Label>, ForgeError> {
        let idx = load_issue_index(self.spine.as_ref(), owner, repo).await?;
        Ok(effective_labels(&idx))
    }

    /// Apply `f` to every pull request's label name list; saves only when
    /// something changed. The caller already holds the issue lock.
    async fn cascade_pulls<F>(&self, owner: &str, repo: &str, f: F) -> Result<(), ForgeError>
    where
        F: Fn(&mut Vec<String>) -> bool,
    {
        let _g = self.locks.pulls.lock(owner, repo).await;
        let Some(bytes) = self.spine.load(PULLS_KIND, owner, repo).await? else {
            return Ok(());
        };
        let mut doc: Value = serde_json::from_slice(&bytes)?;
        let mut touched = false;
        if let Some(pulls) = doc.get_mut("pulls").and_then(Value::as_object_mut) {
            for pr in pulls.values_mut() {
                let mut names = names_of(pr);
                if !names.is_empty() && f(&mut names) {
                    set_names(pr, &names);
                    touched = true;
                }
            }
        }
        if touched {
            self.spine
                .store(PULLS_KIND, owner, repo, &serde_json::to_vec_pretty(&doc)?)
                .await?;
        }
        Ok(())
    }

    /// `/api/repos/<o>/<r>/labels[/<name>]` (JSS `apiLabelsHandler`).
    pub(crate) async fn h_api_labels(
        &self,
        req: &ForgeRequest,
        agent: &ForgeAgent,
        owner: &str,
        repo: &str,
        tail: &[String],
    ) -> Result<ForgeResponse, ForgeError> {
        let m = req.method.to_ascii_uppercase();
        match tail {
            [] => match m.as_str() {
                "GET" | "HEAD" => {
                    let defs = self.label_defs(owner, repo).await?;
                    Ok(json_resp(200, &json!({ "labels": defs })))
                }
                "POST" => self.api_label_create(req, agent, owner, repo).await,
                _ => Ok(api_err(405, "method not allowed")),
            },
            [name] => match m.as_str() {
                "PATCH" => self.api_label_patch(req, agent, owner, repo, name).await,
                "DELETE" => self.api_label_delete(agent, owner, repo, name).await,
                _ => Ok(api_err(405, "method not allowed")),
            },
            _ => Ok(api_err(404, "not found")),
        }
    }

    fn label_owner_gate(agent: &ForgeAgent, owner: &str) -> Option<ForgeResponse> {
        if matches!(agent, ForgeAgent::Anonymous) {
            return Some(unauthorised());
        }
        if agent.owner() != Some(owner) {
            return Some(api_err(403, "only the repo owner may manage labels"));
        }
        None
    }

    async fn api_label_create(
        &self,
        req: &ForgeRequest,
        agent: &ForgeAgent,
        owner: &str,
        repo: &str,
    ) -> Result<ForgeResponse, ForgeError> {
        let body = read_json_body(req);
        if let Some(r) = Self::label_owner_gate(agent, owner) {
            return Ok(r);
        }
        let Some(p) = body else {
            return Ok(api_err(400, "invalid JSON body"));
        };
        let lname = p.get("name").and_then(Value::as_str).map_or("", str::trim);
        if !valid_label_name(lname) {
            return Ok(api_err(422, "label name required (1-50 printable chars)"));
        }
        let Some(color) = p
            .get("color")
            .and_then(Value::as_str)
            .filter(|c| valid_label_color(c))
        else {
            return Ok(api_err(422, "color must be 6 hex digits"));
        };
        let color = color.to_ascii_lowercase();
        let _g = self.locks.issues.lock(owner, repo).await;
        let mut idx = load_issue_index(self.spine.as_ref(), owner, repo).await?;
        let defs = ensure_labels(&mut idx);
        if defs
            .iter()
            .any(|d| d.name.to_lowercase() == lname.to_lowercase())
        {
            return Ok(api_err(409, "label exists"));
        }
        defs.push(Label {
            name: lname.to_string(),
            color: color.clone(),
        });
        save_issue_index(self.spine.as_ref(), owner, repo, &idx).await?;
        Ok(json_resp(201, &json!({"name": lname, "color": color})))
    }

    async fn api_label_patch(
        &self,
        req: &ForgeRequest,
        agent: &ForgeAgent,
        owner: &str,
        repo: &str,
        label: &str,
    ) -> Result<ForgeResponse, ForgeError> {
        let body = read_json_body(req);
        if let Some(r) = Self::label_owner_gate(agent, owner) {
            return Ok(r);
        }
        let Some(p) = body else {
            return Ok(api_err(400, "invalid JSON body"));
        };
        let _g = self.locks.issues.lock(owner, repo).await;
        let mut idx = load_issue_index(self.spine.as_ref(), owner, repo).await?;
        let defs = ensure_labels(&mut idx);
        let Some(pos) = defs.iter().position(|d| d.name == label) else {
            return Ok(api_err(404, "not found"));
        };
        let mut new_name = defs[pos].name.clone();
        if let Some(n) = p.get("name") {
            let n = n.as_str().map_or("", str::trim);
            if !valid_label_name(n) {
                return Ok(api_err(422, "label name required (1-50 printable chars)"));
            }
            if n != defs[pos].name
                && defs
                    .iter()
                    .enumerate()
                    .any(|(i, d)| i != pos && d.name.to_lowercase() == n.to_lowercase())
            {
                return Ok(api_err(409, "label exists"));
            }
            new_name = n.to_string();
        }
        let mut new_color = defs[pos].color.clone();
        if let Some(c) = p.get("color") {
            let Some(c) = c.as_str().filter(|c| valid_label_color(c)) else {
                return Ok(api_err(422, "color must be 6 hex digits"));
            };
            new_color = c.to_ascii_lowercase();
        }
        let old_name = std::mem::replace(&mut defs[pos].name, new_name.clone());
        defs[pos].color = new_color.clone();
        if new_name != old_name {
            for i in idx.issues.values_mut() {
                rename_in(&mut i.labels, &old_name, &new_name);
            }
        }
        save_issue_index(self.spine.as_ref(), owner, repo, &idx).await?;
        if new_name != old_name {
            let (o, n) = (old_name, new_name.clone());
            self.cascade_pulls(owner, repo, move |names| rename_in(names, &o, &n))
                .await?;
        }
        Ok(json_resp(
            200,
            &json!({"name": new_name, "color": new_color}),
        ))
    }

    async fn api_label_delete(
        &self,
        agent: &ForgeAgent,
        owner: &str,
        repo: &str,
        label: &str,
    ) -> Result<ForgeResponse, ForgeError> {
        if let Some(r) = Self::label_owner_gate(agent, owner) {
            return Ok(r);
        }
        let _g = self.locks.issues.lock(owner, repo).await;
        let mut idx = load_issue_index(self.spine.as_ref(), owner, repo).await?;
        let defs = ensure_labels(&mut idx);
        let Some(pos) = defs.iter().position(|d| d.name == label) else {
            return Ok(api_err(404, "not found"));
        };
        defs.remove(pos);
        for i in idx.issues.values_mut() {
            remove_from(&mut i.labels, label);
        }
        save_issue_index(self.spine.as_ref(), owner, repo, &idx).await?;
        let l = label.to_string();
        self.cascade_pulls(owner, repo, move |names| remove_from(names, &l))
            .await?;
        Ok(json_resp(200, &json!({"name": label, "deleted": true})))
    }

    /// `PUT …/{issues,pulls}/<n>/labels {labels: [names]}`: replace an item's
    /// label set. Repo owner or the item's author; every name must exist in
    /// the repo's label set (names are validated, never invented).
    ///
    /// Pull-request routes call this with [`ItemKind::Pull`].
    ///
    /// # Errors
    ///
    /// Spine I/O and corruption errors; request problems are returned as
    /// `Ok` JSON error responses (401, 400, 422, 404, 403).
    pub async fn put_item_labels(
        &self,
        req: &ForgeRequest,
        agent: &ForgeAgent,
        owner: &str,
        repo: &str,
        number: u64,
        kind: ItemKind,
    ) -> Result<ForgeResponse, ForgeError> {
        let body = read_json_body(req);
        if matches!(agent, ForgeAgent::Anonymous) {
            return Ok(unauthorised());
        }
        let Some(arr) = body
            .as_ref()
            .and_then(|b| b.get("labels"))
            .and_then(Value::as_array)
        else {
            return Ok(api_err(400, "body must be { labels: [names] }"));
        };
        if arr.len() > LABELS_PER_ITEM {
            return Ok(api_err(
                422,
                &format!("at most {LABELS_PER_ITEM} labels per item"),
            ));
        }
        let defs = self.label_defs(owner, repo).await?;
        let mut names: Vec<String> = Vec::new();
        for n in arr {
            match n.as_str().filter(|s| defs.iter().any(|d| d.name == *s)) {
                Some(s) => {
                    if !names.iter().any(|x| x == s) {
                        names.push(s.to_string());
                    }
                }
                None => {
                    let shown: String = n
                        .as_str()
                        .map_or_else(|| n.to_string(), str::to_string)
                        .chars()
                        .take(60)
                        .collect();
                    return Ok(api_err(422, &format!("unknown label: {shown}")));
                }
            }
        }
        let may = |author: &str| agent.owner() == Some(owner) || agent.author_id() == author;
        match kind {
            ItemKind::Issue => {
                let _g = self.locks.issues.lock(owner, repo).await;
                let mut idx = load_issue_index(self.spine.as_ref(), owner, repo).await?;
                let Some(item) = idx.issues.get_mut(&number) else {
                    return Ok(api_err(404, "not found"));
                };
                if !may(&item.author) {
                    return Ok(api_err(
                        403,
                        "only the repo owner or the item author may set labels",
                    ));
                }
                item.labels = names.clone();
                save_issue_index(self.spine.as_ref(), owner, repo, &idx).await?;
            }
            ItemKind::Pull => {
                let _g = self.locks.pulls.lock(owner, repo).await;
                let Some(bytes) = self.spine.load(PULLS_KIND, owner, repo).await? else {
                    return Ok(api_err(404, "not found"));
                };
                let mut doc: Value = serde_json::from_slice(&bytes)?;
                let Some(item) = doc
                    .get_mut("pulls")
                    .and_then(|p| p.get_mut(number.to_string()))
                else {
                    return Ok(api_err(404, "not found"));
                };
                let author = item.get("author").and_then(Value::as_str).unwrap_or("");
                if !may(author) {
                    return Ok(api_err(
                        403,
                        "only the repo owner or the item author may set labels",
                    ));
                }
                set_names(item, &names);
                self.spine
                    .store(PULLS_KIND, owner, repo, &serde_json::to_vec_pretty(&doc)?)
                    .await?;
            }
        }
        Ok(json_resp(200, &json!({"number": number, "labels": names})))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::tests::{casey, dana, fixture, get_json, rq};
    use crate::spine::issues::{IssueEntry, IssueState};

    async fn call(
        svc: &ForgeService,
        method: &str,
        path: &str,
        body: &str,
        agent: ForgeAgent,
    ) -> (u16, Value) {
        let r = svc.handle(rq(method, path, "", body), agent).await.unwrap();
        (
            r.status,
            serde_json::from_slice(&r.body).unwrap_or(Value::Null),
        )
    }

    async fn seed_issues(svc: &ForgeService) {
        let mut idx = load_issue_index(svc.spine.as_ref(), "casey", "demo")
            .await
            .unwrap();
        for (title, author) in [
            ("Clone fails", "https://pod.example/dana/profile/card#me"),
            ("Second", "https://pod.example/casey/profile/card#me"),
            ("Docs typo", "https://pod.example/dana/profile/card#me"),
        ] {
            idx.allocate(IssueEntry {
                number: 0,
                title: title.into(),
                state: IssueState::Open,
                author: author.into(),
                created_at: 1,
                thread: vec![],
                labels: vec![],
            });
        }
        save_issue_index(svc.spine.as_ref(), "casey", "demo", &idx)
            .await
            .unwrap();
    }

    // JSS "GitHub's default label set is served before any label was ever touched"
    #[tokio::test]
    async fn default_set_is_served_untouched() {
        let (_td, svc, _) = fixture();
        let (st, v) = get_json(
            &svc,
            "/forge/api/repos/casey/demo/labels",
            "",
            ForgeAgent::Anonymous,
        )
        .await;
        assert_eq!(st, 200);
        assert_eq!(
            v["labels"],
            json!([
                {"name":"bug","color":"d73a4a"},
                {"name":"enhancement","color":"a2eeef"},
                {"name":"documentation","color":"0075ca"},
                {"name":"question","color":"d876e3"},
                {"name":"wontfix","color":"ffffff"},
            ])
        );
    }

    // JSS "label CRUD is owner-only; create validates color and 409s duplicates"
    #[tokio::test]
    async fn crud_is_owner_only_validates_and_409s() {
        let (_td, svc, _) = fixture();
        let url = "/forge/api/repos/casey/demo/labels";
        let b = r#"{"name":"triage","color":"00ff00"}"#;
        assert_eq!(
            call(&svc, "POST", url, b, ForgeAgent::Anonymous).await.0,
            401
        );
        assert_eq!(call(&svc, "POST", url, b, dana()).await.0, 403);
        let (st, v) = call(&svc, "POST", url, b, casey()).await;
        assert_eq!(st, 201);
        assert_eq!(v, json!({"name":"triage","color":"00ff00"}));
        assert_eq!(call(&svc, "POST", url, b, casey()).await.0, 409);
        assert_eq!(
            call(&svc, "POST", url, r#"{"name":"x","color":"red"}"#, casey())
                .await
                .0,
            422
        );
        assert_eq!(
            call(
                &svc,
                "POST",
                url,
                r#"{"name":"","color":"00ff00"}"#,
                casey()
            )
            .await
            .0,
            422
        );
        assert_eq!(call(&svc, "POST", url, "garbage", casey()).await.0, 400);
        // upper-case duplicate is a duplicate too
        assert_eq!(
            call(
                &svc,
                "POST",
                url,
                r#"{"name":"TRIAGE","color":"00ff00"}"#,
                casey()
            )
            .await
            .0,
            409
        );
        let (_, l) = get_json(&svc, url, "", ForgeAgent::Anonymous).await;
        let names: Vec<&str> = l["labels"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x["name"].as_str().unwrap())
            .collect();
        assert_eq!(
            names,
            vec![
                "bug",
                "enhancement",
                "documentation",
                "question",
                "wontfix",
                "triage"
            ]
        );
    }

    // JSS "owner labels an issue ... JSON is additive" + "?label= filters" + "a non-owner non-author cannot set labels"
    #[tokio::test]
    async fn assignment_resolution_filter_and_authorisation() {
        let (_td, svc, _) = fixture();
        seed_issues(&svc).await;
        call(
            &svc,
            "POST",
            "/forge/api/repos/casey/demo/labels",
            r#"{"name":"triage","color":"00ff00"}"#,
            casey(),
        )
        .await;
        let put = |n: u32, body: &'static str, a: ForgeAgent| {
            let svc = svc.clone();
            async move {
                call(
                    &svc,
                    "PUT",
                    &format!("/forge/api/repos/casey/demo/issues/{n}/labels"),
                    body,
                    a,
                )
                .await
            }
        };
        let (st, v) = put(2, r#"{"labels":["bug","triage"]}"#, casey()).await;
        assert_eq!(st, 200);
        assert_eq!(v, json!({"number":2,"labels":["bug","triage"]}));
        let (_, t) = get_json(
            &svc,
            "/forge/api/repos/casey/demo/issues/2",
            "",
            ForgeAgent::Anonymous,
        )
        .await;
        assert_eq!(
            t["labels"],
            json!([{"name":"bug","color":"d73a4a"},{"name":"triage","color":"00ff00"}])
        );
        let (_, li) = get_json(
            &svc,
            "/forge/api/repos/casey/demo/issues",
            "label=triage",
            ForgeAgent::Anonymous,
        )
        .await;
        let nums: Vec<u64> = li["issues"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i["number"].as_u64().unwrap())
            .collect();
        assert_eq!(nums, vec![2]);
        let (_, none) = get_json(
            &svc,
            "/forge/api/repos/casey/demo/issues",
            "state=closed&label=triage",
            ForgeAgent::Anonymous,
        )
        .await;
        assert_eq!(none["issues"], json!([]));
        // authorisation
        assert_eq!(put(2, r#"{"labels":["bug"]}"#, dana()).await.0, 403);
        assert_eq!(
            put(2, r#"{"labels":["bug"]}"#, ForgeAgent::Anonymous)
                .await
                .0,
            401
        );
        assert_eq!(
            put(2, r#"{"labels":["no-such-label"]}"#, casey()).await.0,
            422
        );
        assert_eq!(put(2, r#"{"nope":1}"#, casey()).await.0, 400);
        assert_eq!(put(99, r#"{"labels":["bug"]}"#, casey()).await.0, 404);
        let too_many = format!(r#"{{"labels":[{}]}}"#, vec!["\"bug\""; 21].join(","));
        assert_eq!(
            put(2, Box::leak(too_many.into_boxed_str()), casey())
                .await
                .0,
            422
        );
        // the item author may label without owning the repo (dana authored #3)
        assert_eq!(
            put(3, r#"{"labels":["question","question"]}"#, dana())
                .await
                .0,
            200
        );
        let (_, t3) = get_json(
            &svc,
            "/forge/api/repos/casey/demo/issues/3",
            "",
            ForgeAgent::Anonymous,
        )
        .await;
        assert_eq!(
            t3["labels"].as_array().unwrap().len(),
            1,
            "duplicates collapse"
        );
    }

    // JSS "label rename cascades onto items; delete cascades OFF issues and pulls"
    #[tokio::test]
    async fn rename_and_delete_cascade_over_issues_and_pulls() {
        let (_td, svc, _) = fixture();
        seed_issues(&svc).await;
        let base = "/forge/api/repos/casey/demo";
        call(
            &svc,
            "POST",
            &format!("{base}/labels"),
            r#"{"name":"triage","color":"00ff00"}"#,
            casey(),
        )
        .await;
        call(
            &svc,
            "PUT",
            &format!("{base}/issues/2/labels"),
            r#"{"labels":["bug","triage"]}"#,
            casey(),
        )
        .await;
        // a pull request index, as another feature would write it
        svc.spine
            .store(
                PULLS_KIND,
                "casey",
                "demo",
                br#"{"next":6,"pulls":{"5":{"number":5,"author":"https://pod.example/dana/profile/card#me","labels":["enhancement","triage"]}}}"#,
            )
            .await
            .unwrap();
        let (st, v) = call(
            &svc,
            "PATCH",
            &format!("{base}/labels/triage"),
            r#"{"name":"needs-triage","color":"112233"}"#,
            casey(),
        )
        .await;
        assert_eq!(st, 200);
        assert_eq!(v, json!({"name":"needs-triage","color":"112233"}));
        let (_, t) = get_json(&svc, &format!("{base}/issues/2"), "", ForgeAgent::Anonymous).await;
        let names: Vec<&str> = t["labels"]
            .as_array()
            .unwrap()
            .iter()
            .map(|l| l["name"].as_str().unwrap())
            .collect();
        assert_eq!(
            names,
            vec!["bug", "needs-triage"],
            "rename followed the assignment"
        );
        let pulls: Value = serde_json::from_slice(
            &svc.spine
                .load(PULLS_KIND, "casey", "demo")
                .await
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            pulls["pulls"]["5"]["labels"],
            json!(["enhancement", "needs-triage"])
        );
        // rename conflicts and unknown labels
        assert_eq!(
            call(
                &svc,
                "PATCH",
                &format!("{base}/labels/needs-triage"),
                r#"{"name":"BUG"}"#,
                casey()
            )
            .await
            .0,
            409
        );
        assert_eq!(
            call(
                &svc,
                "PATCH",
                &format!("{base}/labels/needs-triage"),
                r#"{"color":"zzz"}"#,
                casey()
            )
            .await
            .0,
            422
        );
        assert_eq!(
            call(&svc, "PATCH", &format!("{base}/labels/nope"), "{}", casey())
                .await
                .0,
            404
        );
        assert_eq!(
            call(
                &svc,
                "PATCH",
                &format!("{base}/labels/needs-triage"),
                "{}",
                dana()
            )
            .await
            .0,
            403
        );
        // delete cascades
        let (st, _) = call(
            &svc,
            "DELETE",
            &format!("{base}/labels/needs-triage"),
            "",
            casey(),
        )
        .await;
        assert_eq!(st, 200);
        let (_, t) = get_json(&svc, &format!("{base}/issues/2"), "", ForgeAgent::Anonymous).await;
        assert_eq!(t["labels"].as_array().unwrap().len(), 1);
        assert_eq!(
            call(
                &svc,
                "DELETE",
                &format!("{base}/labels/needs-triage"),
                "",
                casey()
            )
            .await
            .0,
            404,
            "second delete is a clean 404"
        );
        assert_eq!(
            call(
                &svc,
                "DELETE",
                &format!("{base}/labels/enhancement"),
                "",
                casey()
            )
            .await
            .0,
            200
        );
        let pulls: Value = serde_json::from_slice(
            &svc.spine
                .load(PULLS_KIND, "casey", "demo")
                .await
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            pulls["pulls"]["5"]["labels"],
            json!([]),
            "delete cascades off pull requests too"
        );
        assert_eq!(
            call(
                &svc,
                "DELETE",
                &format!("{base}/labels/bug"),
                "",
                ForgeAgent::Anonymous
            )
            .await
            .0,
            401
        );
    }

    // JSS "owner labels a pull request" via the reusable entry point
    #[tokio::test]
    async fn pull_labels_via_put_item_labels() {
        let (_td, svc, _) = fixture();
        svc.spine
            .store(PULLS_KIND, "casey", "demo", br#"{"next":6,"pulls":{"5":{"number":5,"author":"https://pod.example/dana/profile/card#me"}}}"#)
            .await
            .unwrap();
        let req = rq("PUT", "/x", "", r#"{"labels":["enhancement"]}"#);
        let r = svc
            .put_item_labels(&req, &casey(), "casey", "demo", 5, ItemKind::Pull)
            .await
            .unwrap();
        assert_eq!(r.status, 200);
        let r = svc
            .put_item_labels(
                &req,
                &ForgeAgent::Anonymous,
                "casey",
                "demo",
                5,
                ItemKind::Pull,
            )
            .await
            .unwrap();
        assert_eq!(r.status, 401);
        let stranger = ForgeAgent::Pod {
            webid: "https://pod.example/eve/profile/card#me".into(),
            username: "eve".into(),
        };
        let r = svc
            .put_item_labels(&req, &stranger, "casey", "demo", 5, ItemKind::Pull)
            .await
            .unwrap();
        assert_eq!(r.status, 403);
        let r = svc
            .put_item_labels(&req, &casey(), "casey", "demo", 6, ItemKind::Pull)
            .await
            .unwrap();
        assert_eq!(r.status, 404);
        let pulls: Value = serde_json::from_slice(
            &svc.spine
                .load(PULLS_KIND, "casey", "demo")
                .await
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(pulls["pulls"]["5"]["labels"], json!(["enhancement"]));
    }

    #[test]
    fn chips_use_luminance_text_and_escape() {
        let chips = chips_html(&[
            Label {
                name: "bug".into(),
                color: "d73a4a".into(),
            },
            Label {
                name: "triage".into(),
                color: "00ff00".into(),
            },
            Label {
                name: "<x>".into(),
                color: "\"onload=".into(),
            },
        ]);
        assert!(chips.contains("background:#d73a4a;color:#ffffff"));
        assert!(chips.contains("background:#00ff00;color:#1f2328"));
        assert!(chips.contains(">bug</span>"));
        assert!(chips.contains("&lt;x&gt;"));
        assert!(!chips.contains("onload"), "corrupt colours cannot inject");
    }
}
