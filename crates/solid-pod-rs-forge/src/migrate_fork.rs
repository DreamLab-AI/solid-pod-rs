//! The fork sweep of the boot migration (SP-GIT-02 Commit B2).
//!
//! A fork made from a pre-release mirror store with `clone --local`
//! hardlinks the mirror's packs, held objects included, and keeps serving
//! them after the mirror itself is rebuilt. After every mirror-class store
//! is migrated, this pass:
//!
//! 1. reads every served store's `forge.parent` (a config error makes the
//!    pass incomplete, decision 28), parsed with the readers' path-segment
//!    rule (a lineage that still does not parse is unknown: checked against
//!    every mirror-class report, never letting one be stamped), and walks
//!    each fork's lineage to its root, transitively, cycle-safe, bounded by
//!    the store count;
//! 2. collects the migration reports of every mirror-class ancestor: their
//!    `.dropped` sets are the trigger, their `.held` sets the ref filter. A
//!    fork whose chain passes a store still behind a journal (any owner),
//!    or whose ancestor's report cannot be read, has nothing to be checked
//!    against and is gated. A fork whose chain stops at a store that is gone
//!    is checked against every mirror-class report;
//! 3. rebuilds a fork holding any object of an unstamped ancestor's dropped
//!    set, or any object its own refs do not reach (F2: pruned from the
//!    parent before migration), (object presence, never the marker:
//!    decision 19) with the same
//!    machinery as a mirror-class store: journal, staging, verification,
//!    seal, swap, recovery. Every ref but `refs/mirror/*` and
//!    `refs/replace/*` is copied, pull-request heads included, unless it
//!    reaches an inherited held object (D1: dropped and reported);
//! 4. stamps `forksCleanAt` into every mirror-class report once a complete
//!    pass found all its forks clean, so the check stops for that parent;
//! 5. moves `repos/<owner>/.fork-*.tmp` directories older than an hour (a
//!    crashed fork build) into recovery (D4; smart-HTTP already refuses
//!    them, so this is cleanup).

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::{
    dir_state, journal_exists, journal_path, journaled, migrate_store, now_secs, read_journal,
    read_regular, reports, run_in, served_stores, store_migration_id, sync_dir, with_suffix,
    write_synced, Built, Detected, DroppedRef, Input, JournalRead, Kind, Outcome, MAX_HELD_IDS,
    STORE_BUDGET,
};
use crate::forks::{
    config_entries, parse_lineage_value, read_lineage_checked, stored_lineage, StoredLineage,
    FORGE_REFS,
};
use crate::mirror_record::{is_hex64, MirrorStore, StoredRecord};

/// How old a `.fork-*.tmp` directory must be before it is swept (D4: a
/// heuristic against a fork build still running in another instance).
const PARTIAL_FORK_AGE: Duration = Duration::from_secs(3600);

/// One migrated mirror-class ancestor's report, as the sweep reads it.
#[derive(Debug, Clone)]
struct AncestorReport {
    id: String,
    path: PathBuf,
    held: PathBuf,
    dropped: PathBuf,
    /// The SHAs of the branches and tags the migration copied.
    roots: Vec<String>,
    /// `forksCleanAt` is set: every fork was found clean.
    stamped: bool,
}

/// What one fork is checked and rebuilt against.
#[derive(Debug, Clone, Default)]
pub(super) struct Plan {
    /// `forge.parent`, `<owner>/<name>`.
    parent: String,
    /// The fork has a mirror record: it also gets the mirror's config and
    /// marker.
    followed: bool,
    /// The reports of its migrated mirror-class ancestors.
    reports: Vec<AncestorReport>,
    /// Why it cannot be checked (it is gated), if so.
    gate: Option<String>,
    /// Its lineage, or an ancestor's, does not parse: it is checked against
    /// every mirror-class report and never lets one be stamped.
    unknown: bool,
}

impl Plan {
    pub(super) fn parent(&self) -> &str {
        &self.parent
    }

    pub(super) fn followed(&self) -> bool {
        self.followed
    }

    /// Why the fork cannot be checked against its ancestors, if so.
    pub(super) fn gate(&self) -> Option<&str> {
        self.gate.as_deref()
    }

    /// The ids of every ancestor report the fork is rebuilt against, sorted.
    pub(super) fn report_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self.reports.iter().map(|r| r.id.clone()).collect();
        ids.sort();
        ids.dedup();
        ids
    }

    /// The reports whose dropped sets still trigger a check.
    fn triggers(&self) -> Vec<&AncestorReport> {
        self.reports.iter().filter(|r| !r.stamped).collect()
    }
}

/// A served store's lineage.
#[derive(Debug, Clone)]
enum Lineage {
    Root,
    Parent(String, String),
    /// `forge.parent` is present but does not parse: its value.
    Unknown(String),
    /// The config could not be read: the pass is incomplete.
    Unreadable,
}

/// What the sweep came to.
pub(super) struct Swept {
    /// Every fork's outcome, for the pass's tally.
    pub(super) outcomes: Vec<Outcome>,
    /// Every store's lineage was read and every listing completed.
    pub(super) listed: bool,
}

/// The fork sweep. `mirror_complete` says whether the mirror-class pass
/// completed; reports are stamped only if it did and this pass did too.
pub(super) async fn sweep(plugin: &Path, mirror_complete: bool) -> Swept {
    sweep_partial_forks(plugin);
    let (stores, stores_listed) = served_stores(plugin);
    let mut listed = stores_listed;
    let mut lineage = BTreeMap::new();
    for (owner, name) in &stores {
        let dir = plugin.join("repos").join(owner).join(format!("{name}.git"));
        let l = match read_lineage_checked(&dir) {
            Ok(StoredLineage::Parent(p)) => Lineage::Parent(p.owner, p.name),
            Ok(StoredLineage::Unknown(raw)) => Lineage::Unknown(raw),
            Ok(StoredLineage::None) => Lineage::Root,
            Err(e) => {
                tracing::error!(owner = %owner, name = %name, error = %e.kind(), "forge: repository config not read; every fork is refused");
                listed = false;
                Lineage::Unreadable
            }
        };
        lineage.insert((owner.clone(), name.clone()), l);
    }
    // Forks: served stores with a parent, and fork journals (a fork whose
    // store is in recovery mid-migration names its parent in the journal).
    let mut targets: BTreeMap<(String, String), String> = BTreeMap::new();
    for (key, l) in &lineage {
        match l {
            Lineage::Parent(o, n) => {
                targets.insert(key.clone(), format!("{o}/{n}"));
            }
            Lineage::Unknown(raw) => {
                targets.insert(key.clone(), raw.clone());
            }
            Lineage::Root | Lineage::Unreadable => {}
        }
    }
    let (journals, journals_listed) = journaled(plugin);
    listed &= journals_listed;
    for (owner, name) in journals {
        let Some(path) = journal_path(plugin, &owner, &name) else {
            continue;
        };
        if let JournalRead::Present(j) = read_journal(&path) {
            if j.class == "fork" {
                if let Some(parent) = j.parent {
                    targets.entry((owner, name)).or_insert(parent);
                }
            }
        }
    }
    let mut outcomes = Vec::new();
    let mut blocked: BTreeSet<String> = BTreeSet::new();
    let mut every: Option<Result<Vec<AncestorReport>, String>> = None;
    for ((owner, name), parent) in &targets {
        let plan = plan_for(plugin, owner, name, parent, &lineage, &mut every);
        let kind = Kind::Fork(plan.clone());
        let outcome = if journal_exists(plugin, owner, name) {
            migrate_store(plugin, owner, name, &kind).await
        } else {
            match detect(plugin, owner, name, &plan).await {
                Detected::Skip | Detected::Clean => Outcome::Skipped,
                _ => migrate_store(plugin, owner, name, &kind).await,
            }
        };
        blocked.extend(stamp_blocks(&plan, outcome));
        if outcome == Outcome::Ungated {
            listed = false;
        }
        outcomes.push(outcome);
    }
    if mirror_complete && listed && !blocked.contains("") {
        stamp_clean(plugin, &blocked, &mut every);
    }
    Swept { outcomes, listed }
}

/// The report ids a fork's plan and outcome keep from being stamped; the
/// empty id blocks every report. A gated plan blocks every report (F3: it
/// holds only the reports collected before the gate, and the ancestors
/// beyond are unknown), and so does a fork of unknown lineage.
fn stamp_blocks(plan: &Plan, outcome: Outcome) -> Vec<String> {
    if plan.gate.is_some() || plan.unknown {
        return vec![String::new()];
    }
    match outcome {
        Outcome::Migrated | Outcome::Skipped => Vec::new(),
        Outcome::Failed | Outcome::Ungated => {
            let mut ids = plan.report_ids();
            if plan.reports.is_empty() {
                // Gated before its ancestors were known: block them all.
                ids.push(String::new());
            }
            ids
        }
    }
}

/// The plan of fork `<owner>/<name>` whose parent is `parent`: walk the
/// lineage to its root (cycle-safe, at most one step per store), collecting
/// every mirror-class ancestor's reports.
fn plan_for(
    plugin: &Path,
    owner: &str,
    name: &str,
    parent: &str,
    lineage: &BTreeMap<(String, String), Lineage>,
    every: &mut Option<Result<Vec<AncestorReport>, String>>,
) -> Plan {
    let mut plan = Plan {
        parent: parent.to_string(),
        followed: is_hex64(owner)
            && !matches!(
                MirrorStore::new(plugin).load(owner, name),
                StoredRecord::Missing
            ),
        ..Plan::default()
    };
    let mut visited = BTreeSet::from([(owner.to_string(), name.to_string())]);
    let mut next = parse_lineage_value(parent).map(|p| (p.owner, p.name));
    let mut orphan = false;
    if next.is_none() {
        // A lineage that does not parse: its ancestors are unknown.
        plan.unknown = true;
        orphan = true;
    }
    while let Some(at) = next.take() {
        if visited.len() > lineage.len() + 1 || !visited.insert(at.clone()) {
            break; // a cycle, or longer than the store count
        }
        let (o, n) = (&at.0, &at.1);
        // An ancestor behind a journal, under any owner (a fork that failed
        // its own rebuild included), gates its descendants.
        if journal_exists(plugin, o, n) {
            plan.gate = Some(format!("ancestor {o}/{n} is behind a migration journal"));
            return plan;
        }
        if is_hex64(o) {
            match mirror_reports(plugin, o, n) {
                Ok(found) => plan.reports.extend(found),
                Err(e) => {
                    plan.gate = Some(format!("ancestor {o}/{n}'s migration report: {e}"));
                    return plan;
                }
            }
        }
        let dir = plugin.join("repos").join(o).join(format!("{n}.git"));
        match dir_state(&dir) {
            Ok(true) => match lineage.get(&at) {
                Some(Lineage::Parent(po, pn)) => next = Some((po.clone(), pn.clone())),
                Some(Lineage::Unknown(_)) => {
                    plan.unknown = true;
                    orphan = true;
                }
                Some(Lineage::Root) => {}
                Some(Lineage::Unreadable) | None => {
                    plan.gate = Some(format!("ancestor {o}/{n}'s lineage could not be read"));
                    return plan;
                }
            },
            Ok(false) => orphan = true,
            Err(e) => {
                plan.gate = Some(format!("ancestor {o}/{n}: {e}"));
                return plan;
            }
        }
    }
    if orphan {
        // The chain stops at a store that is gone: its own ancestors are
        // unknown, so check against every mirror-class report.
        match every.get_or_insert_with(|| every_mirror_report(plugin)) {
            Ok(all) => plan.reports.extend(all.iter().cloned()),
            Err(e) => {
                plan.gate = Some(format!("the migration reports could not be listed: {e}"));
                return plan;
            }
        }
    }
    let mut seen = HashSet::new();
    plan.reports.retain(|r| seen.insert(r.id.clone()));
    plan
}

/// The mirror-class migration reports of `<owner>/<name>`, with their
/// `.held` and `.dropped` files. Any report that cannot be read, or lacks
/// either file, is an error (the fork is then gated).
fn mirror_reports(plugin: &Path, owner: &str, name: &str) -> Result<Vec<AncestorReport>, String> {
    let dir = plugin.join("mirror-recovery").join(owner);
    let mut out = Vec::new();
    for path in reports(&dir, name)? {
        if let Some(r) = read_report(&path)? {
            out.push(r);
        }
    }
    Ok(out)
}

/// Every mirror-class migration report under `mirror-recovery/`.
fn every_mirror_report(plugin: &Path) -> Result<Vec<AncestorReport>, String> {
    let root = plugin.join("mirror-recovery");
    let mut out = Vec::new();
    for (owner, path) in super::names_in(&root)? {
        if !is_hex64(&owner) || !dir_state(&path)? {
            continue;
        }
        for (file, entry) in super::names_in(&path)? {
            let Some(stem) = file.strip_suffix(".migration.json") else {
                continue;
            };
            let is_report = stem
                .rsplit_once(".git.")
                .is_some_and(|(_, ts)| super::all_digits(ts));
            if is_report {
                if let Some(r) = read_report(&entry)? {
                    out.push(r);
                }
            }
        }
    }
    Ok(out)
}

/// One report, if it is a mirror-class report.
fn read_report(path: &Path) -> Result<Option<AncestorReport>, String> {
    let bytes = read_regular(path).map_err(|e| format!("not read: {}", e.kind()))?;
    let v: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|e| format!("not parsed: {e}"))?;
    if v.get("class").and_then(|c| c.as_str()) != Some("mirror") {
        return Ok(None);
    }
    let id = v
        .get("id")
        .and_then(|i| i.as_str())
        .ok_or("no id")?
        .to_string();
    let file = path
        .to_str()
        .and_then(|p| p.strip_suffix(".migration.json"))
        .ok_or("not a report name")?;
    let stem = PathBuf::from(file);
    let (held, dropped) = (with_suffix(&stem, ".held"), with_suffix(&stem, ".dropped"));
    for f in [&held, &dropped] {
        if !std::fs::symlink_metadata(f).is_ok_and(|m| m.is_file()) {
            return Err("its held or dropped list is missing".into());
        }
    }
    let roots = v
        .get("copied")
        .and_then(|c| c.as_array())
        .map(|refs| {
            refs.iter()
                .filter(|r| {
                    r.get("ref")
                        .and_then(|n| n.as_str())
                        .is_some_and(super::is_root)
                })
                .filter_map(|r| r.get("sha").and_then(|s| s.as_str()))
                .filter(|s| super::is_sha40(s))
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    Ok(Some(AncestorReport {
        id,
        path: path.to_path_buf(),
        held,
        dropped,
        roots,
        stamped: v.get("forksCleanAt").is_some(),
    }))
}

/// Fork detection: `Rebuild` when the fork holds any object of an
/// unstamped ancestor's dropped set, `Clean` when it holds none (or this
/// sweep already rebuilt it against every such report), `Error` when it
/// cannot be checked.
pub(super) async fn detect(plugin: &Path, owner: &str, name: &str, plan: &Plan) -> Detected {
    let served = plugin.join("repos").join(owner).join(format!("{name}.git"));
    match dir_state(&served) {
        Ok(true) => {}
        Ok(false) => return Detected::Skip,
        Err(e) => return Detected::Error(e),
    }
    if let Some(g) = &plan.gate {
        return Detected::Error(g.clone());
    }
    let triggers = plan.triggers();
    if triggers.is_empty() {
        return Detected::Clean;
    }
    if rebuilt_against(plugin, owner, name, &served, &triggers) {
        return Detected::Clean;
    }
    let files: Vec<PathBuf> = triggers.iter().map(|r| r.dropped.clone()).collect();
    match holds_any(&served, files).await {
        Ok(true) => Detected::Rebuild,
        // F2: an object pruned from the parent before migration is in no
        // report, but a fork taken earlier still holds it in its hardlinked
        // packs, unreachable from its own refs. A rebuild copies only ref
        // closures, so it removes such objects.
        Ok(false) => match holds_unreachable(&served).await {
            Ok(true) => Detected::Rebuild,
            Ok(false) => Detected::Clean,
            Err(e) => Detected::Error(e),
        },
        Err(e) => Detected::Error(e),
    }
}

/// Whether the store at `git_dir` holds any object the refs a rebuild keeps
/// do not reach. `cat-file --batch-all-objects` lists every object once (it
/// is deduplicated across packs and loose objects), and every object such a
/// ref reaches is among them, so it lists more than the `rev-list --objects`
/// walk exactly when one is outside it. The walk excludes `refs/mirror/*`
/// and `refs/replace/*`, which [`select`] drops: a ref the rebuild drops must
/// not make an object count as reachable. Both walks are streamed and
/// counted, never held, with replace objects and grafts disabled; either
/// failing is an error (the fork is then gated, never found clean).
async fn holds_unreachable(git_dir: &Path) -> Result<bool, String> {
    let mut all: u64 = 0;
    super::for_each_line(
        git_dir,
        &[
            "cat-file",
            "--batch-all-objects",
            "--batch-check=%(objectname)",
        ],
        None,
        STORE_BUDGET,
        |_| {
            all += 1;
            Ok(super::Flow::Go)
        },
    )
    .await?;
    let mut reached: u64 = 0;
    super::for_each_line(
        git_dir,
        &[
            "rev-list",
            "--objects",
            "--exclude=refs/mirror/*",
            "--exclude=refs/replace/*",
            "--all",
        ],
        None,
        STORE_BUDGET,
        |_| {
            reached += 1;
            Ok(super::Flow::Go)
        },
    )
    .await?;
    Ok(all > reached)
}

/// Whether the served fork carries the migration id of a fork report that
/// lists every one of `triggers` among its ancestors: it was rebuilt against
/// them, and what it still holds of their dropped sets its own refs reach
/// (risk 4), so it is not rebuilt again.
fn rebuilt_against(
    plugin: &Path,
    owner: &str,
    name: &str,
    served: &Path,
    triggers: &[&AncestorReport],
) -> bool {
    let Some(id) = store_migration_id(served) else {
        return false;
    };
    let dir = plugin.join("mirror-recovery").join(owner);
    let Ok(found) = reports(&dir, name) else {
        return false;
    };
    found.iter().any(|path| {
        let Some(v) = read_regular(path)
            .ok()
            .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
        else {
            return false;
        };
        let covered: BTreeSet<&str> = v
            .get("ancestors")
            .and_then(|a| a.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_str()).collect())
            .unwrap_or_default();
        v.get("class").and_then(|c| c.as_str()) == Some("fork")
            && v.get("id").and_then(|i| i.as_str()) == Some(id.as_str())
            && triggers.iter().all(|t| covered.contains(t.id.as_str()))
    })
}

/// Whether the store at `git_dir` holds any id listed in `files`
/// (`cat-file --batch-check`, the lists streamed, stopping at the first hit).
async fn holds_any(git_dir: &Path, files: Vec<PathBuf>) -> Result<bool, String> {
    let mut hit = false;
    super::for_each_line_input(
        git_dir,
        &["cat-file", "--batch-check=%(objectname) %(objecttype)"],
        Input::Files(files),
        STORE_BUDGET,
        |line| {
            if line.ends_with(" missing") {
                Ok(super::Flow::Go)
            } else {
                hit = true;
                Ok(super::Flow::Stop)
            }
        },
    )
    .await?;
    Ok(hit)
}

/// The inherited held set: the union of the ancestors' `.held` files,
/// bounded by [`MAX_HELD_IDS`].
pub(super) fn inherited_held(plan: &Plan) -> Result<HashSet<String>, String> {
    use std::io::BufRead;
    let mut held = HashSet::new();
    for r in &plan.reports {
        let m = std::fs::symlink_metadata(&r.held).map_err(|e| format!("held list: {e}"))?;
        if !m.file_type().is_file() {
            return Err("a held list is not a regular file".into());
        }
        let f = std::fs::File::open(&r.held).map_err(|e| format!("held list: {e}"))?;
        for line in std::io::BufReader::new(f).lines() {
            let line = line.map_err(|e| format!("held list: {e}"))?;
            if line.is_empty() {
                continue;
            }
            if !super::is_sha40(&line) {
                return Err("a held list holds something other than object ids".into());
            }
            if held.len() >= MAX_HELD_IDS {
                return Err(format!(
                    "the inherited held set passed {MAX_HELD_IDS} objects"
                ));
            }
            held.insert(line);
        }
    }
    Ok(held)
}

/// The ancestors' roots that `source` holds (checked first: `rev-list
/// --not` fails on an object it does not have, C12).
pub(super) async fn present_roots(source: &Path, plan: &Plan) -> Result<Vec<String>, String> {
    let mut all: Vec<String> = plan
        .reports
        .iter()
        .flat_map(|r| r.roots.iter().cloned())
        .collect();
    all.sort();
    all.dedup();
    if all.is_empty() {
        return Ok(all);
    }
    let mut input = Vec::with_capacity(all.len() * 41);
    for sha in &all {
        input.extend_from_slice(sha.as_bytes());
        input.push(b'\n');
    }
    let out = super::run_with_input(
        source,
        &["cat-file", "--batch-check=%(objectname) %(objecttype)"],
        input,
        STORE_BUDGET,
    )
    .await?;
    if !out.status.success() {
        return Err("git cat-file --batch-check failed".into());
    }
    let present: Vec<String> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| !l.ends_with(" missing"))
        .filter_map(|l| l.split(' ').next())
        .filter(|id| super::is_sha40(id))
        .map(str::to_string)
        .collect();
    Ok(present)
}

/// Fork ref selection into `built`: every ref but `refs/mirror/*` and
/// `refs/replace/*` (and names unsafe on a push command line), each copied
/// only if it reaches nothing in `held` beyond `ancestor_roots` (D1: a ref
/// that does is dropped and reported as `reaches-held`).
pub(super) async fn select(
    source: &Path,
    refs: Vec<(String, Option<String>, String)>,
    built: &mut Built,
    held: &HashSet<String>,
    ancestor_roots: &[String],
) -> Result<(), String> {
    for (sha, name, lossy) in refs {
        let reason = match name.as_deref() {
            None => "unsafe-name",
            Some(r) if !super::safe_ref(r) || !super::is_sha40(&sha) => "unsafe-name",
            Some(r) if r.starts_with("refs/mirror/") => "mirror",
            Some(r) if r.starts_with("refs/replace/") => "replace",
            Some(r) => {
                if super::reaches_held(source, &sha, ancestor_roots, held).await? {
                    "reaches-held"
                } else {
                    built.copied.insert(r.to_string(), sha);
                    continue;
                }
            }
        };
        built.dropped.push(DroppedRef {
            name: lossy,
            sha,
            reason,
        });
    }
    Ok(())
}

/// A fork's config: an allow-list of the old one (`forge.parent`,
/// `http.receivepack` when a boolean, and `uploadpack.hideRefs` /
/// `transfer.hideRefs` entries equal to `refs/forge/`). The old config is
/// never copied whole: it is legacy-written and may name hooks or
/// alternates. No served config: `receive.denyDeletes` would stop the owner
/// deleting branches.
pub(super) async fn write_fork_config(source: &Path, staging: &Path) -> Result<(), String> {
    let bytes = read_regular(&source.join("config"))
        .map_err(|e| format!("the old config could not be read: {}", e.kind()))?;
    let text = String::from_utf8_lossy(&bytes);
    let parent = match stored_lineage(&text) {
        StoredLineage::Parent(p) => p.full(),
        // Kept as read, so the rebuilt fork stays one of unknown lineage.
        StoredLineage::Unknown(raw) => raw,
        StoredLineage::None => return Err("the old config names no forge.parent".into()),
    };
    let mut sets: Vec<(&str, String)> = vec![("forge.parent", parent)];
    for (section, key, value) in config_entries(&text) {
        match (section.as_str(), key.as_str()) {
            ("http", "receivepack") if matches!(value.as_str(), "true" | "false") => {
                sets.push(("http.receivepack", value));
            }
            ("uploadpack", "hiderefs") if value == FORGE_REFS => {
                sets.push(("uploadpack.hideRefs", value));
            }
            ("transfer", "hiderefs") if value == FORGE_REFS => {
                sets.push(("transfer.hideRefs", value));
            }
            _ => {}
        }
    }
    for (key, value) in sets {
        run_in(
            staging,
            staging,
            &["config", "--local", "--add", key, &value],
            None,
            Duration::from_secs(15),
            None,
        )
        .await?;
    }
    Ok(())
}

/// Stamp `forksCleanAt` into every unstamped mirror-class report whose id
/// is not `blocked` (a fork checked against it was not found clean).
fn stamp_clean(
    plugin: &Path,
    blocked: &BTreeSet<String>,
    every: &mut Option<Result<Vec<AncestorReport>, String>>,
) {
    let all = match every.get_or_insert_with(|| every_mirror_report(plugin)) {
        Ok(all) => all,
        Err(e) => {
            tracing::warn!(error = %e, "forge: migration reports not listed; none stamped");
            return;
        }
    };
    for r in all
        .iter()
        .filter(|r| !r.stamped && !blocked.contains(&r.id))
    {
        if let Err(e) = stamp(&r.path) {
            tracing::warn!(error = %e, "forge: migration report not stamped");
        }
    }
}

/// Add `forksCleanAt` to the report at `path`, every other field kept: a
/// temporary file, `fsync`, rename, `fsync` the directory.
fn stamp(path: &Path) -> Result<(), String> {
    let bytes = read_regular(path).map_err(|e| format!("not read: {}", e.kind()))?;
    let mut v: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|e| format!("not parsed: {e}"))?;
    let o = v.as_object_mut().ok_or("not an object")?;
    o.insert("forksCleanAt".into(), now_secs().into());
    let out = serde_json::to_vec_pretty(&v).map_err(|e| e.to_string())?;
    let tmp = with_suffix(path, ".tmp");
    write_synced(&tmp, &out).map_err(|e| format!("not written: {e}"))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("not written: {e}"))?;
    path.parent()
        .map_or(Ok(()), sync_dir)
        .map_err(|e| format!("not synced: {e}"))
}

/// D4: move every `repos/<owner>/.fork-*.tmp` directory older than
/// [`PARTIAL_FORK_AGE`] to `mirror-recovery/<owner>/<entry>.<ts>`. Cleanup
/// only (smart-HTTP refuses such paths), so errors are logged.
fn sweep_partial_forks(plugin: &Path) {
    let Ok(owners) = super::names_in(&plugin.join("repos")) else {
        return;
    };
    for (owner, owner_dir) in owners {
        if !crate::ownership::valid_name_segment(&owner) {
            continue;
        }
        let Ok(entries) = super::names_in(&owner_dir) else {
            continue;
        };
        for (file, entry) in entries {
            if !(file.starts_with(".fork-") && file.ends_with(".tmp")) {
                continue;
            }
            let Ok(meta) = std::fs::symlink_metadata(&entry) else {
                continue;
            };
            let old = meta
                .modified()
                .ok()
                .and_then(|t| t.elapsed().ok())
                .is_some_and(|age| age >= PARTIAL_FORK_AGE);
            if !meta.is_dir() || !old {
                continue;
            }
            let dir = plugin.join("mirror-recovery").join(&owner);
            let dest = dir.join(format!("{file}.{}", now_secs()));
            let moved = std::fs::create_dir_all(&dir)
                .and_then(|()| std::fs::rename(&entry, &dest))
                .and_then(|()| sync_dir(&dir))
                .and_then(|()| sync_dir(&owner_dir));
            match moved {
                Ok(()) => {
                    tracing::info!(owner = %owner, entry = %file, "forge: stale partial fork moved to recovery");
                }
                Err(e) => {
                    tracing::warn!(owner = %owner, entry = %file, error = %e, "forge: stale partial fork not moved");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Item 3 (F3): a plan gated partway up its lineage holds only the
    /// reports collected before the gate; the ancestors beyond it are
    /// unknown, so every report is kept from being stamped, whatever the
    /// fork's outcome.
    #[test]
    fn a_gate_partway_up_the_lineage_blocks_every_report() {
        let report = AncestorReport {
            id: "r1".into(),
            path: PathBuf::new(),
            held: PathBuf::new(),
            dropped: PathBuf::new(),
            roots: Vec::new(),
            stamped: false,
        };
        let plan = Plan {
            parent: "f/sample".into(),
            reports: vec![report],
            gate: Some("ancestor carol/sample: transient".into()),
            ..Plan::default()
        };
        for outcome in [
            Outcome::Failed,
            Outcome::Ungated,
            Outcome::Skipped,
            Outcome::Migrated,
        ] {
            assert!(
                stamp_blocks(&plan, outcome).contains(&String::new()),
                "{outcome:?}: a gated plan blocked only {:?}",
                stamp_blocks(&plan, outcome)
            );
        }
    }
}
