//! Tests for the ungated migration module (SP-GIT-02 Commit B1): the
//! hoisted constants, the smart-HTTP refusal of invalid repository names,
//! and the boot migration of pre-release served stores.

/// Test 20: the hoisted constants are pinned byte for byte, the mirror
/// engine uses the very same items, the lock path is the engine's for a
/// 64-hex owner, and the `awaitsMigration` key matches the record's serde.
#[test]
fn t20_hoisted_constants_and_record_key_are_pinned() {
    assert_eq!(
        crate::migrate::RECEIVE_PACK,
        "git -c core.fsmonitor=false -c core.hooksPath=/dev/null \
         -c core.sshCommand=false -c commit.gpgSign=false -c receive.fsckObjects=true \
         -c receive.denyDeletes=true receive-pack"
    );
    assert_eq!(
        crate::migrate::SERVED_CONFIG,
        [
            ("core.hooksPath", "/dev/null"),
            ("receive.fsckObjects", "true"),
            ("receive.denyDeletes", "true"),
        ]
    );
    let owner = "a".repeat(64);
    let plugin = std::path::Path::new("/srv/plugin");
    assert_eq!(
        crate::migrate::lock_path(plugin, &owner, "sample"),
        Some(
            plugin
                .join("mirror-work")
                .join("locks")
                .join(&owner)
                .join("sample.lock")
        )
    );
    assert_eq!(
        crate::migrate::lock_path(plugin, "bob", "fork-1"),
        Some(plugin.join("mirror-work/locks/bob/fork-1.lock")),
        "a fork owner is a valid name segment"
    );
    assert_eq!(crate::migrate::lock_path(plugin, "..", "x"), None);
    assert_eq!(
        crate::migrate::lock_path(plugin, "bob", ".fork-x.tmp"),
        None
    );
    #[cfg(feature = "mirror")]
    assert_eq!(
        crate::mirror::MirrorStore::new(plugin).lock_file(&owner, "sample"),
        crate::migrate::lock_path(plugin, &owner, "sample"),
        "the engine's lock file and the migration's differ"
    );
    let json =
        format!(r#"{{"pubkey":"{owner}","name":"sample","events":0,"awaitsMigration":true}}"#);
    let rec: crate::mirror_record::MirrorRecord = serde_json::from_str(&json).unwrap();
    assert!(rec.awaits_migration);
    let back = serde_json::to_value(&rec).unwrap();
    assert_eq!(back[crate::migrate::AWAITS_MIGRATION_KEY], true, "{back}");
    assert_eq!(crate::migrate::AWAITS_MIGRATION_KEY, "awaitsMigration");
}

// ---- shared helpers -------------------------------------------------------

use std::path::{Path, PathBuf};
use std::process::Command;

/// Run git with a clean, fixed identity; panics with stderr on failure.
fn git(cwd: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .args([
            "-c",
            "user.name=Agent",
            "-c",
            "user.email=agent@example.org",
        ])
        .args(args)
        .current_dir(cwd)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_DATE", "1700000000 +0000")
        .env("GIT_COMMITTER_DATE", "1700000000 +0000")
        .output()
        .expect("git runs");
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn http_backend() -> PathBuf {
    let out = Command::new("git")
        .arg("--exec-path")
        .output()
        .expect("git runs");
    let p = PathBuf::from(String::from_utf8_lossy(&out.stdout).trim()).join("git-http-backend");
    assert!(
        p.is_file(),
        "git-http-backend not found under `git --exec-path`; this test needs it and does not skip"
    );
    p
}

/// A forge at `plugin` whose git CGI uses the located `git-http-backend`.
fn forge_with_backend(plugin: &Path) -> crate::ForgeService {
    let mut forge =
        crate::ForgeService::new(crate::ForgeConfig::default(), plugin).expect("forge builds");
    forge.git = std::sync::Arc::new(
        solid_pod_rs_git::service::GitHttpService::new(plugin.join("repos"))
            .with_backend_path(http_backend()),
    );
    forge
}

fn req(method: &str, path: &str, query: &str) -> crate::ForgeRequest {
    crate::ForgeRequest {
        method: method.into(),
        path: path.into(),
        query: query.into(),
        headers: vec![],
        raw_body: bytes::Bytes::new(),
        host_url: None,
    }
}

/// A bare store at `dir` holding one commit on `main`; returns its sha.
fn bare_with_commit(home: &Path, dir: &Path, body: &str) -> String {
    let work = home.join(format!("work-{}", uuid::Uuid::new_v4().simple()));
    std::fs::create_dir_all(&work).unwrap();
    git(&work, &["init", "--quiet", "-b", "main"]);
    std::fs::write(work.join("f.txt"), body).unwrap();
    git(&work, &["add", "-A"]);
    git(&work, &["commit", "--quiet", "-m", "c"]);
    let sha = git(&work, &["rev-parse", "HEAD"]);
    std::fs::create_dir_all(dir.parent().unwrap()).unwrap();
    git(
        home,
        &[
            "clone",
            "--quiet",
            "--bare",
            work.to_str().unwrap(),
            dir.to_str().unwrap(),
        ],
    );
    sha
}

/// Decision 22: smart HTTP refuses a repository path whose name is not a
/// valid segment (a crashed fork's `.fork-*.tmp` directory), instead of
/// passing it on to the CGI, which exports every bare repository under
/// `repos/`. A normal repository of the same owner is the positive control.
#[tokio::test]
async fn t22_smart_http_refuses_a_dot_named_bare_repo() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path();
    let plugin = home.join("plugin");
    let tmp_sha = bare_with_commit(home, &plugin.join("repos/bob/.fork-x.tmp"), "secret\n");
    let ok_sha = bare_with_commit(home, &plugin.join("repos/bob/real.git"), "public\n");
    let forge = forge_with_backend(&plugin);
    let adv = |path: &str| req("GET", path, "service=git-upload-pack");

    let ok = forge
        .handle(
            adv("/forge/bob/real.git/info/refs"),
            crate::ForgeAgent::Anonymous,
        )
        .await
        .unwrap();
    assert_eq!(
        ok.status,
        200,
        "control: {}",
        String::from_utf8_lossy(&ok.body)
    );
    assert!(
        String::from_utf8_lossy(&ok.body).contains(&ok_sha),
        "control: the normal repository is advertised"
    );

    for path in [
        "/forge/bob/.fork-x.tmp/info/refs",
        "/forge/bob/.fork-x.tmp/git-upload-pack",
    ] {
        let mut r = adv(path);
        if path.ends_with("git-upload-pack") {
            r.method = "POST".into();
            r.query = String::new();
            r.headers = vec![(
                "content-type".into(),
                "application/x-git-upload-pack-request".into(),
            )];
            let want = format!("want {tmp_sha}\n");
            r.raw_body = bytes::Bytes::from(format!("{:04x}{want}00000009done\n", want.len() + 4));
        }
        let got = forge.handle(r, crate::ForgeAgent::Anonymous).await;
        let (status, body) = match got {
            Ok(resp) => (resp.status, resp.body.to_vec()),
            Err(e) => (e.status_code(), e.to_string().into_bytes()),
        };
        let text = String::from_utf8_lossy(&body);
        assert_eq!(status, 404, "{path} -> {status}: {text}");
        assert!(
            !text.contains(&tmp_sha),
            "{path} advertised the tmp repo: {text}"
        );
        assert!(!body.windows(4).any(|w| w == b"PACK"), "{path} sent a pack");
    }
}

// ---- Commit B1 (c): boot migration of mirror-class stores ----------------
//
// Every fixture is C15-hard: the held objects sit in a pack with a `.keep`
// file, and a non-mirror ref (`refs/misc/stash-held`) reaches the held
// commit, so deleting `refs/mirror` plus `gc --prune=now` in place would
// still leave them (test 5 pins this). The paths and JSON keys of the
// journal and the recovery report are spelt out here, so these tests fail
// on assertions, not on compile errors, before the migration exists.

const APPROVED: &str = "b1-approved-public-bytes\n";
const OLD: &str = "b1-old-approved-bytes\n";
const NEW: &str = "b1-new-approved-bytes\n";
const HELD: &str = "b1-held-secret-bytes\n";
const HELD_SUBJECT: &str = "b1-held-subject";
const MARKER: &str = "mirror-publication-v1";
/// The file at the root of a rebuilt store naming the migration that built
/// it (fix round 1, item 5).
const MIGRATION_ID: &str = "migration-id";

/// A legacy (pre-release) served store, in today's pre-release layout.
struct Legacy {
    _tmp: tempfile::TempDir,
    home: PathBuf,
    plugin: PathBuf,
    owner: String,
    served: PathBuf,
    /// `main` one: `f.txt` = OLD, `public.txt` = APPROVED.
    m1: String,
    /// `main` two (the served `main`): `f.txt` = NEW.
    m2: String,
    /// The held side commit off `m2`: `f.txt` = OLD again (C16), `held.txt`.
    held: String,
    held_blob: String,
    old_blob: String,
    foreign: String,
}

/// How the fixture's `main` and tag got into the served store.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Shape {
    /// The legacy engine wrote `refs/heads/main`; the owner tagged in place.
    Engine,
    /// The owner pushed `main` and tag `v1` before the repository was
    /// followed (decision 2's case, test 9).
    OwnerPushed,
}

fn owner_of(seed: u8) -> String {
    hex::encode([seed; 32])
}

fn commit(work: &Path, files: &[(&str, &str)], subject: &str) -> String {
    for (f, body) in files {
        std::fs::write(work.join(f), body).unwrap();
    }
    git(work, &["add", "-A"]);
    git(work, &["commit", "--quiet", "-m", subject]);
    git(work, &["rev-parse", "HEAD"])
}

fn legacy(seed: u8, shape: Shape) -> Legacy {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().to_path_buf();
    let plugin = home.join("plugin");
    let owner = owner_of(seed);
    let up = home.join("up");
    std::fs::create_dir_all(&up).unwrap();
    git(&up, &["init", "--quiet", "-b", "main"]);
    let m1 = commit(
        &up,
        &[("f.txt", OLD), ("public.txt", APPROVED)],
        "b1 approved one",
    );
    let old_blob = git(&up, &["rev-parse", "HEAD:f.txt"]);
    let m2 = commit(&up, &[("f.txt", NEW)], "b1 approved two");
    git(&up, &["checkout", "--quiet", "-b", "side"]);
    let held = commit(&up, &[("f.txt", OLD), ("held.txt", HELD)], HELD_SUBJECT);
    let held_blob = git(&up, &["rev-parse", "HEAD:held.txt"]);
    git(&up, &["checkout", "--quiet", "main"]);
    if shape == Shape::OwnerPushed {
        git(&up, &["tag", "-a", "v1", "-m", "release one", &m2]);
    }
    let served = plugin.join("repos").join(&owner).join("sample.git");
    std::fs::create_dir_all(served.parent().unwrap()).unwrap();
    let s = served.to_str().unwrap();
    git(&home, &["init", "--bare", "--quiet", "-b", "main", s]);
    let up_s = up.to_str().unwrap();
    if shape == Shape::OwnerPushed {
        git(
            &up,
            &[
                "push",
                "--quiet",
                s,
                "main:main",
                "refs/tags/v1:refs/tags/v1",
            ],
        );
    }
    git(
        &served,
        &["config", "--add", "uploadpack.hideRefs", "refs/mirror"],
    );
    git(
        &served,
        &["config", "--add", "transfer.hideRefs", "refs/mirror"],
    );
    git(
        &served,
        &[
            "fetch",
            "--quiet",
            "--no-tags",
            up_s,
            "+refs/heads/*:refs/mirror/*",
        ],
    );
    if shape == Shape::Engine {
        git(&served, &["update-ref", "refs/heads/main", &m2]);
        git(&served, &["tag", "-a", "v1", "-m", "release one", &m2]);
    }
    git(
        &served,
        &[
            "notes",
            "--ref=commits",
            "add",
            "-m",
            "b1 note on approved",
            &m2,
        ],
    );
    let fork = home.join("forkup");
    std::fs::create_dir_all(&fork).unwrap();
    git(&fork, &["init", "--quiet", "-b", "feat"]);
    let foreign = commit(&fork, &[("foreign.txt", "b1-foreign\n")], "b1 foreign");
    git(
        &served,
        &[
            "fetch",
            "--quiet",
            "--no-tags",
            fork.to_str().unwrap(),
            "+refs/heads/feat:refs/forge/heads/bob/feat",
        ],
    );
    git(&served, &["update-ref", "refs/misc/stash-held", &held]);
    git(&served, &["update-ref", "refs/misc/blob", &held_blob]);
    git(&served, &["repack", "-a", "-d", "-q"]);
    for e in std::fs::read_dir(served.join("objects/pack"))
        .unwrap()
        .flatten()
    {
        let p = e.path();
        if p.extension().is_some_and(|x| x == "pack") {
            std::fs::write(p.with_extension("keep"), b"b1 fixture\n").unwrap();
        }
    }
    Legacy {
        _tmp: tmp,
        home,
        plugin,
        owner,
        served,
        m1,
        m2,
        held,
        held_blob,
        old_blob,
        foreign,
    }
}

fn record_path(plugin: &Path, owner: &str) -> PathBuf {
    plugin.join("mirror").join(owner).join("sample.json")
}

fn write_record(plugin: &Path, owner: &str, body: &[u8]) {
    let f = record_path(plugin, owner);
    std::fs::create_dir_all(f.parent().unwrap()).unwrap();
    std::fs::write(f, body).unwrap();
}

/// A record written before this release: no `isolated` field.
fn pre_release_record(owner: &str) -> String {
    format!(r#"{{"pubkey":"{owner}","name":"sample","events":3,"awaitsMigration":true}}"#)
}

fn journal_of(plugin: &Path, owner: &str) -> PathBuf {
    plugin
        .join("mirror-work")
        .join("migrations")
        .join(owner)
        .join("sample.json")
}

/// The recovery entries `mirror-recovery/<owner>/sample.git.<ts>`.
fn recovery_entries(plugin: &Path, owner: &str) -> Vec<PathBuf> {
    let dir = plugin.join("mirror-recovery").join(owner);
    let mut out: Vec<PathBuf> = std::fs::read_dir(dir)
        .map(|rd| {
            rd.flatten()
                .map(|e| e.path())
                .filter(|p| {
                    let f = p.file_name().unwrap().to_string_lossy().into_owned();
                    f.strip_prefix("sample.git.")
                        .is_some_and(|ts| !ts.is_empty() && ts.bytes().all(|b| b.is_ascii_digit()))
                })
                .collect()
        })
        .unwrap_or_default();
    out.sort();
    out
}

fn sibling(entry: &Path, suffix: &str) -> PathBuf {
    let mut s = entry.as_os_str().to_os_string();
    s.push(suffix);
    PathBuf::from(s)
}

fn has(dir: &Path, spec: &str) -> bool {
    Command::new("git")
        .args(["cat-file", "-e", spec])
        .current_dir(dir)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .is_ok_and(|o| o.status.success())
}

fn refs_of(dir: &Path) -> String {
    git(dir, &["for-each-ref", "--format=%(refname)"])
}

async fn get(forge: &crate::ForgeService, path: String) -> crate::ForgeResponse {
    forge
        .handle(req("GET", &path, ""), crate::ForgeAgent::Anonymous)
        .await
        .expect("the forge answers")
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// Every HTML, JSON, raw and archive reader of the held commit: the
/// responses that are 2xx or carry held bytes.
async fn held_leaks(forge: &crate::ForgeService, o: &str, h: &str) -> Vec<String> {
    let paths = [
        format!("/forge/{o}/sample/raw/{h}/held.txt"),
        format!("/forge/{o}/sample/blob/{h}/held.txt"),
        format!("/forge/{o}/sample/tree/{h}"),
        format!("/forge/{o}/sample/commit/{h}"),
        format!("/forge/api/repos/{o}/sample/commit/{h}"),
        format!("/forge/api/repos/{o}/sample/tree/{h}"),
        format!("/forge/api/repos/{o}/sample/blob/{h}/held.txt"),
        format!("/forge/{o}/sample/archive/{h}.tar.gz"),
    ];
    let mut leaks = Vec::new();
    for p in paths {
        let r = get(forge, p.clone()).await;
        let bytes = contains(&r.body, HELD.trim_end().as_bytes())
            || contains(&r.body, HELD_SUBJECT.as_bytes());
        if (200..300).contains(&r.status) || bytes {
            leaks.push(format!("{p} -> {} (held bytes: {bytes})", r.status));
        }
    }
    leaks
}

fn forge_at(plugin: &Path) -> crate::ForgeService {
    crate::ForgeService::new(crate::ForgeConfig::default(), plugin).expect("forge builds")
}

/// What every migrated fixture must show: held denied on every reader,
/// approved content served exactly, the marker, a recovery entry outside
/// `repos/` with its report files, and no journal left.
async fn assert_migrated(fx: &Legacy, forge: &crate::ForgeService) {
    let (o, h) = (&fx.owner, &fx.held);
    let leaks = held_leaks(forge, o, h).await;
    assert!(
        leaks.is_empty(),
        "held commit served:\n{}",
        leaks.join("\n")
    );
    let raw = get(forge, format!("/forge/{o}/sample/raw/{}/public.txt", fx.m2)).await;
    assert_eq!(
        (raw.status, raw.body.as_ref()),
        (200, APPROVED.as_bytes()),
        "approved raw: {}",
        String::from_utf8_lossy(&raw.body)
    );
    assert!(
        fx.served.join(MARKER).is_file(),
        "the rebuilt store is not marked"
    );
    for spec in [h.as_str(), fx.held_blob.as_str()] {
        assert!(!has(&fx.served, spec), "{spec} is in the served store");
    }
    assert!(!fx.served.join("objects/info/alternates").exists());
    assert!(
        !journal_of(&fx.plugin, o).exists(),
        "journal left: {}",
        std::fs::read_to_string(journal_of(&fx.plugin, o)).unwrap_or_default()
    );
    let entries = recovery_entries(&fx.plugin, o);
    assert_eq!(entries.len(), 1, "recovery entries: {entries:?}");
    assert!(
        has(&entries[0], &fx.held_blob),
        "the recovery copy keeps the old store whole"
    );
    for suffix in [".migration.json", ".held", ".dropped"] {
        assert!(
            sibling(&entries[0], suffix).is_file(),
            "no {suffix} report file"
        );
    }
    // Fix round 1, item 5: the rebuilt store carries its migration id, and
    // the report names the same id.
    let id = std::fs::read_to_string(fx.served.join(MIGRATION_ID))
        .expect("the rebuilt store carries its migration id");
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(sibling(&entries[0], ".migration.json")).unwrap())
            .unwrap();
    assert_eq!(
        report["id"].as_str(),
        Some(id.trim()),
        "the report and the store name different migrations: {report}"
    );
    let held_list = std::fs::read_to_string(sibling(&entries[0], ".held")).unwrap();
    assert!(
        held_list.lines().any(|l| l == fx.held_blob),
        ".held does not list the held blob"
    );
    let dropped = std::fs::read_to_string(sibling(&entries[0], ".dropped")).unwrap();
    assert!(
        dropped.lines().any(|l| l == fx.held_blob),
        ".dropped lacks the held blob"
    );
    let mut walk = vec![fx.plugin.join("repos")];
    while let Some(d) = walk.pop() {
        for e in std::fs::read_dir(&d).unwrap().flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            assert!(
                !name.contains(".migration.json") && !name.starts_with("sample.git."),
                "recovery data under repos/: {}",
                e.path().display()
            );
            if e.path().is_dir() && d == fx.plugin.join("repos") {
                walk.push(e.path());
            }
        }
    }
}

fn report_of(fx: &Legacy) -> serde_json::Value {
    let entries = recovery_entries(&fx.plugin, &fx.owner);
    let bytes = std::fs::read(sibling(&entries[0], ".migration.json")).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn dropped_reason(report: &serde_json::Value, r: &str) -> Option<String> {
    report["dropped"]
        .as_array()?
        .iter()
        .find(|d| d["ref"] == r)
        .and_then(|d| d["reason"].as_str())
        .map(str::to_string)
}

/// Test 1: a restart migrates a record-bearing legacy store (a pre-release
/// record, `isolated` absent, flagged). The C16 blob (an approved blob the
/// held commit re-adds) stays readable; tag `v1` stays annotated; the notes
/// ref lies outside the roots, so it is dropped, reported and kept in the
/// recovery copy (fix round 1, item 1); the flag is cleared, every other
/// record field kept.
#[tokio::test]
async fn t1_restart_migrates_a_record_bearing_legacy_store() {
    let fx = legacy(201, Shape::Engine);
    write_record(
        &fx.plugin,
        &fx.owner,
        pre_release_record(&fx.owner).as_bytes(),
    );
    let forge = forge_with_backend(&fx.plugin);
    assert_migrated(&fx, &forge).await;
    let o = &fx.owner;
    let old = get(&forge, format!("/forge/{o}/sample/raw/{}/f.txt", fx.m1)).await;
    assert_eq!(
        (old.status, old.body.as_ref()),
        (200, OLD.as_bytes()),
        "the approved blob the held commit re-adds (C16)"
    );
    assert!(has(&fx.served, &fx.old_blob));
    assert_eq!(git(&fx.served, &["cat-file", "-t", "refs/tags/v1"]), "tag");
    assert_eq!(
        git(&fx.served, &["rev-parse", "refs/tags/v1^{commit}"]),
        fx.m2
    );
    // Fix round 1, item 1: only branches and tags are roots. A notes ref's
    // closure leaves theirs, so it is dropped and reported, and the note is
    // kept in the recovery copy.
    let refs = refs_of(&fx.served);
    assert!(
        !refs.contains("refs/notes/"),
        "a notes ref was copied: {refs}"
    );
    let report = report_of(&fx);
    assert_eq!(
        dropped_reason(&report, "refs/notes/commits").as_deref(),
        Some("outside-roots"),
        "{report}"
    );
    let recovery = recovery_entries(&fx.plugin, o).remove(0);
    assert_eq!(
        git(&recovery, &["notes", "--ref=commits", "show", &fx.m2]),
        "b1 note on approved"
    );
    assert_eq!(
        git(&fx.served, &["symbolic-ref", "HEAD"]),
        "refs/heads/main"
    );
    let rec: serde_json::Value =
        serde_json::from_slice(&std::fs::read(record_path(&fx.plugin, o)).unwrap()).unwrap();
    assert!(
        rec.get("awaitsMigration").is_none(),
        "flag not cleared: {rec}"
    );
    assert_eq!(rec["events"], 3, "another record field changed: {rec}");
    assert!(rec.get("isolated").is_none(), "a field was added: {rec}");
    // Smart HTTP: held not fetchable by id; approved is.
    let want = |sha: &str| {
        let mut r = req(
            "POST",
            &format!("/forge/{o}/sample.git/git-upload-pack"),
            "",
        );
        r.headers = vec![(
            "content-type".into(),
            "application/x-git-upload-pack-request".into(),
        )];
        let w = format!("want {sha}\n");
        r.raw_body = bytes::Bytes::from(format!("{:04x}{w}00000009done\n", w.len() + 4));
        r
    };
    let ok = forge
        .handle(want(&fx.m2), crate::ForgeAgent::Anonymous)
        .await
        .unwrap();
    assert!(
        contains(&ok.body, b"PACK"),
        "control: approved want returns a pack"
    );
    let held = forge
        .handle(want(&fx.held), crate::ForgeAgent::Anonymous)
        .await
        .unwrap();
    assert!(!contains(&held.body, b"PACK"), "held want returned a pack");
}

/// Tests 2 and 3: a lost-record legacy store (hideRefs and `refs/mirror`,
/// no record) is migrated. Ungated, so it runs with and without `mirror`
/// (test 3 is this test under default features).
#[tokio::test]
async fn t2_t3_lost_record_legacy_store_is_migrated() {
    let fx = legacy(202, Shape::Engine);
    assert!(!record_path(&fx.plugin, &fx.owner).exists());
    let forge = forge_at(&fx.plugin);
    assert_migrated(&fx, &forge).await;
    assert!(
        !record_path(&fx.plugin, &fx.owner).exists(),
        "a record was created"
    );
}

/// Test 4: a ref pointing straight at a held blob (`refs/misc/blob`, which
/// `for-each-ref --contains` cannot see, C11) is dropped as outside the
/// roots and reported; and
/// the object-level verification refuses a staging store that holds it.
#[tokio::test]
async fn t4_direct_held_blob_ref_is_dropped_and_verify_catches_it() {
    let fx = legacy(204, Shape::Engine);
    let forge = forge_at(&fx.plugin);
    assert_migrated(&fx, &forge).await;
    let refs = refs_of(&fx.served);
    assert!(!refs.contains("refs/misc/blob"), "{refs}");
    assert!(!refs.contains("refs/misc/stash-held"), "{refs}");
    let report = report_of(&fx);
    assert_eq!(
        dropped_reason(&report, "refs/misc/blob").as_deref(),
        Some("outside-roots"),
        "{report}"
    );
    assert_eq!(
        dropped_reason(&report, "refs/misc/stash-held").as_deref(),
        Some("outside-roots"),
        "{report}"
    );
    // The verification alone: a staging store that took the blob.
    let recovery = recovery_entries(&fx.plugin, &fx.owner).remove(0);
    let staging = fx.home.join("planted.git");
    git(
        &fx.home,
        &[
            "init",
            "--bare",
            "--quiet",
            "-b",
            "main",
            staging.to_str().unwrap(),
        ],
    );
    git(
        &recovery,
        &[
            "push",
            "--quiet",
            staging.to_str().unwrap(),
            &format!("{}:refs/heads/main", fx.m2),
            &format!("{}:refs/misc/blob", fx.held_blob),
        ],
    );
    let want: std::collections::BTreeMap<String, String> = [
        ("refs/heads/main".to_string(), fx.m2.clone()),
        ("refs/misc/blob".to_string(), fx.held_blob.clone()),
    ]
    .into_iter()
    .collect();
    let held: std::collections::HashSet<String> =
        std::fs::read_to_string(sibling(&recovery, ".held"))
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect();
    let verdict = crate::migrate::verify(&recovery, &staging, &want, &held).await;
    assert!(
        verdict.as_ref().is_err_and(|e| e.contains("held")),
        "verification passed a staging store holding a held blob: {verdict:?}"
    );
    // Fix round 1, item 1: with an empty held set the same staging store
    // still fails, because the blob lies outside the roots' closure.
    let none = std::collections::HashSet::new();
    let verdict = crate::migrate::verify(&recovery, &staging, &want, &none).await;
    assert!(
        verdict
            .as_ref()
            .is_err_and(|e| e.contains("outside the roots")),
        "verification passed an object outside the roots: {verdict:?}"
    );
    // Control: the same staging without the blob ref and object passes the
    // ref and held checks.
    let clean = fx.home.join("clean.git");
    git(
        &fx.home,
        &[
            "init",
            "--bare",
            "--quiet",
            "-b",
            "main",
            clean.to_str().unwrap(),
        ],
    );
    git(
        &recovery,
        &[
            "push",
            "--quiet",
            clean.to_str().unwrap(),
            &format!("{}:refs/heads/main", fx.m2),
        ],
    );
    let want_clean: std::collections::BTreeMap<String, String> =
        [("refs/heads/main".to_string(), fx.m2.clone())]
            .into_iter()
            .collect();
    let ok = crate::migrate::verify(&recovery, &clean, &want_clean, &held).await;
    assert!(
        ok.is_ok(),
        "control: a clean staging store fails verification: {ok:?}"
    );
}

/// Test 5: the mutant guard. The rejected in-place method (delete
/// `refs/mirror`, then `gc --prune=now`) run on a copy of the fixture leaves
/// the held blob present, so a delete-plus-gc implementation would fail the
/// tests above. This pins the fixture's hardness; it does not exercise the
/// migration.
#[test]
fn t5_fixture_survives_delete_and_gc() {
    let fx = legacy(205, Shape::Engine);
    let copy = fx.home.join("mutant.git");
    let out = Command::new("cp")
        .args(["-a", fx.served.to_str().unwrap(), copy.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success());
    let mirror_refs = git(
        &copy,
        &["for-each-ref", "--format=delete %(refname)", "refs/mirror"],
    );
    let mut child = Command::new("git")
        .args(["update-ref", "--stdin"])
        .current_dir(&copy)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .stdin(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    {
        use std::io::Write;
        child
            .stdin
            .take()
            .unwrap()
            .write_all(format!("{mirror_refs}\n").as_bytes())
            .unwrap();
    }
    assert!(child.wait().unwrap().success());
    assert_eq!(git(&copy, &["for-each-ref", "refs/mirror"]), "");
    git(&copy, &["gc", "--quiet", "--prune=now"]);
    assert!(
        has(&copy, &fx.held_blob),
        "the fixture is weak: delete-plus-gc removed the held blob"
    );
}

/// Test 9: an owner-pushed repository at a 64-hex owner that became a
/// mirror keeps the owner's tag (decision 2), and held is denied.
#[tokio::test]
async fn t9_owner_pushed_mirror_keeps_its_tag() {
    let fx = legacy(209, Shape::OwnerPushed);
    write_record(
        &fx.plugin,
        &fx.owner,
        format!(r#"{{"pubkey":"{}","name":"sample","events":1}}"#, fx.owner).as_bytes(),
    );
    let tag = git(&fx.served, &["rev-parse", "refs/tags/v1"]);
    let forge = forge_at(&fx.plugin);
    assert_migrated(&fx, &forge).await;
    assert_eq!(
        git(&fx.served, &["rev-parse", "refs/tags/v1"]),
        tag,
        "tag v1 lost or moved"
    );
    assert_eq!(git(&fx.served, &["cat-file", "-t", "refs/tags/v1"]), "tag");
}

/// Test 10: a pull request head fetched into the legacy mirror is not
/// copied; the open pull request's pages degrade without a 5xx; the report
/// lists the head.
#[tokio::test]
async fn t10_mirror_pull_request_head_is_not_copied() {
    let fx = legacy(210, Shape::Engine);
    write_record(
        &fx.plugin,
        &fx.owner,
        pre_release_record(&fx.owner).as_bytes(),
    );
    let spine = crate::FsSpineStore::new(fx.plugin.clone());
    let pr: crate::pulls::PullIndex = serde_json::from_value(serde_json::json!({
        "next": 2,
        "pulls": { "1": {
            "number": 1, "title": "b1 foreign", "state": "open",
            "author": "did:nostr:bob", "createdAt": 1_700_000_000u64, "base": "main",
            "head": { "owner": "bob", "repo": "sample", "ref": "feat" }, "thread": []
        }}
    }))
    .unwrap();
    crate::pulls::save_pull_index(&spine, &fx.owner, "sample", &pr)
        .await
        .unwrap();
    let forge = forge_at(&fx.plugin);
    assert_migrated(&fx, &forge).await;
    assert!(
        !refs_of(&fx.served).contains("refs/forge/heads/"),
        "a PR head was copied"
    );
    assert!(
        !has(&fx.served, &fx.foreign),
        "the foreign head's commit is served"
    );
    let report = report_of(&fx);
    assert_eq!(
        dropped_reason(&report, "refs/forge/heads/bob/feat").as_deref(),
        Some("pull-request-head"),
        "{report}"
    );
    let o = &fx.owner;
    for p in [
        format!("/forge/{o}/sample/pulls/1"),
        format!("/forge/{o}/sample/pulls/1/commits"),
        format!("/forge/{o}/sample/pulls/1/files"),
        format!("/forge/api/repos/{o}/sample/pulls/1"),
    ] {
        let r = get(&forge, p.clone()).await;
        assert!(
            r.status < 500,
            "{p} -> {}: {}",
            r.status,
            String::from_utf8_lossy(&r.body)
        );
    }
}

/// Test 11: a store beside an unreadable record is rebuilt and marked; the
/// record's bytes are unchanged and copied into the report; readers serve
/// the approved content.
#[tokio::test]
async fn t11_unreadable_record_store_is_rebuilt_and_the_record_kept() {
    let fx = legacy(211, Shape::Engine);
    let corrupt: &[u8] = b"{\"pubkey\": \"trunc";
    write_record(&fx.plugin, &fx.owner, corrupt);
    let forge = forge_at(&fx.plugin);
    assert_migrated(&fx, &forge).await;
    assert_eq!(
        std::fs::read(record_path(&fx.plugin, &fx.owner)).unwrap(),
        corrupt
    );
    let report = report_of(&fx);
    use base64::Engine as _;
    assert_eq!(
        report["record"]["bytesBase64"],
        base64::engine::general_purpose::STANDARD.encode(corrupt),
        "{report}"
    );
}

/// Test 14: a second `ForgeService::new` rebuilds nothing: no new recovery
/// entry, the served store unchanged.
#[tokio::test]
async fn t14_restart_is_idempotent() {
    let fx = legacy(214, Shape::Engine);
    write_record(
        &fx.plugin,
        &fx.owner,
        pre_release_record(&fx.owner).as_bytes(),
    );
    let forge = forge_at(&fx.plugin);
    assert_migrated(&fx, &forge).await;
    let snapshot = |d: &Path| {
        (
            git(d, &["for-each-ref", "--format=%(refname) %(objectname)"]),
            git(
                d,
                &[
                    "cat-file",
                    "--batch-all-objects",
                    "--batch-check=%(objectname)",
                ],
            ),
        )
    };
    let before = snapshot(&fx.served);
    let entries = recovery_entries(&fx.plugin, &fx.owner);
    let again = forge_at(&fx.plugin);
    assert_eq!(
        recovery_entries(&fx.plugin, &fx.owner),
        entries,
        "a new recovery entry"
    );
    assert_eq!(snapshot(&fx.served), before, "the served store changed");
    assert_migrated(&fx, &again).await;
}

/// Test 16, child half: run only `ForgeService::new` on the plugin
/// directory named by the environment, then exit.
const T16_CHILD: &str = "SOLID_FORGE_B1_T16_PLUGIN";

/// Test 16: two processes run `ForgeService::new` on one plugin directory at
/// once. Exactly one recovery entry; both succeed; held never served.
#[test]
fn t16_two_processes_migrate_once() {
    if let Ok(dir) = std::env::var(T16_CHILD) {
        let _ = forge_at(Path::new(&dir));
        return;
    }
    let fx = legacy(216, Shape::Engine);
    write_record(
        &fx.plugin,
        &fx.owner,
        pre_release_record(&fx.owner).as_bytes(),
    );
    let me = std::env::current_exe().unwrap();
    let spawn = || {
        Command::new(&me)
            .args([
                "--exact",
                "migrate_tests::t16_two_processes_migrate_once",
                "--nocapture",
            ])
            .env(T16_CHILD, &fx.plugin)
            .spawn()
            .unwrap()
    };
    let (mut a, mut b) = (spawn(), spawn());
    assert!(a.wait().unwrap().success(), "first process failed");
    assert!(b.wait().unwrap().success(), "second process failed");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let forge = forge_at(&fx.plugin);
        assert_migrated(&fx, &forge).await;
    });
}

/// Test 17: `ForgeService::new` inside a current-thread runtime (the
/// default `#[tokio::test]`) migrates without panicking.
#[tokio::test]
async fn t17_new_inside_a_current_thread_runtime() {
    let fx = legacy(217, Shape::Engine);
    let forge = forge_at(&fx.plugin);
    assert_migrated(&fx, &forge).await;
}

/// Test 17, multi-thread flavour.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t17_new_inside_a_multi_thread_runtime() {
    let fx = legacy(218, Shape::Engine);
    let forge = forge_at(&fx.plugin);
    assert_migrated(&fx, &forge).await;
}

/// Test 18: while a migration journal exists, smart HTTP refuses a push
/// into the store (503), whatever the journal's state, and every reader
/// refuses it too, `published` included (fix round 2, item 1).
#[tokio::test]
async fn t18_smart_http_push_is_refused_while_a_journal_exists() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path();
    let plugin = home.join("plugin");
    let owner = owner_of(218);
    let served = plugin.join("repos").join(&owner).join("sample.git");
    let sha = bare_with_commit(home, &served, "owner content\n");
    std::fs::write(served.join(MARKER), format!("{MARKER}\n")).unwrap();
    let forge = forge_with_backend(&plugin);
    let agent = crate::ForgeAgent::Nostr {
        pubkey_hex: owner.clone(),
    };
    let base = format!("/forge/{owner}/sample.git");
    for state in ["published", "building", "failed"] {
        let j = journal_of(&plugin, &owner);
        std::fs::create_dir_all(j.parent().unwrap()).unwrap();
        std::fs::write(
            &j,
            format!(r#"{{"id":"t18","ts":1,"class":"mirror","state":"{state}","recovery":"mirror-recovery/{owner}/sample.git.1","attempts":0}}"#),
        )
        .unwrap();
        let push = forge
            .handle(
                req(
                    "GET",
                    &format!("{base}/info/refs"),
                    "service=git-receive-pack",
                ),
                agent.clone(),
            )
            .await;
        let status = push.map_or_else(|e| e.status_code(), |r| r.status);
        assert_eq!(status, 503, "push with a {state} journal");
        let read = get(&forge, format!("/forge/{owner}/sample/raw/{sha}/f.txt")).await;
        // Fix round 2, item 1: every journal gates, `published` included.
        assert_eq!(read.status, 503, "read with a {state} journal");
    }
}

/// Decision 21: a lost-record legacy store whose copied history holds an
/// object staging's `receive.fsckObjects` rejects (a bad time zone) cannot
/// be migrated. The journal stays, at `failed`, and gates every reader.
#[tokio::test]
async fn t21_failed_migration_keeps_the_store_gated() {
    let fx = legacy(221, Shape::Engine);
    let tree = git(&fx.served, &["rev-parse", &format!("{}^{{tree}}", fx.m2)]);
    let raw = format!(
        "tree {tree}\nparent {}\nauthor t <t@t> 1700000000 +99999\ncommitter t <t@t> 1700000000 +0000\n\nb1 bad zone\n",
        fx.m2
    );
    let mut child = Command::new("git")
        .args([
            "hash-object",
            "--literally",
            "-t",
            "commit",
            "-w",
            "--stdin",
        ])
        .current_dir(&fx.served)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    {
        use std::io::Write;
        child
            .stdin
            .take()
            .unwrap()
            .write_all(raw.as_bytes())
            .unwrap();
    }
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    let bad = String::from_utf8_lossy(&out.stdout).trim().to_string();
    git(&fx.served, &["update-ref", "refs/heads/main", &bad]);
    let forge = forge_at(&fx.plugin);
    let leaks = held_leaks(&forge, &fx.owner, &fx.held).await;
    assert!(
        leaks.is_empty(),
        "held commit served:\n{}",
        leaks.join("\n")
    );
    let o = &fx.owner;
    let approved = get(
        &forge,
        format!("/forge/{o}/sample/raw/{}/public.txt", fx.m2),
    )
    .await;
    assert_eq!(approved.status, 503, "the unmigrated store is not gated");
    let j: serde_json::Value = serde_json::from_slice(
        &std::fs::read(journal_of(&fx.plugin, o)).expect("the journal persists"),
    )
    .unwrap();
    assert_eq!(j["state"], "failed", "{j}");
    assert_eq!(j["attempts"], 1, "{j}");
    assert!(
        j["reason"].as_str().unwrap_or("").contains("badTimezone"),
        "{j}"
    );
    assert!(
        has(&fx.served, &fx.held_blob),
        "the old store is left in place"
    );
    assert!(!fx.served.join(MARKER).exists());
    // No staging is left behind.
    let staging = fx.plugin.join("mirror-work").join("staging").join(o);
    let left: Vec<_> = std::fs::read_dir(&staging)
        .map(|r| r.flatten().count())
        .into_iter()
        .collect();
    assert!(left.iter().all(|n| *n == 0), "staging left: {left:?}");
    // Retries stop at the limit.
    let _ = forge_at(&fx.plugin);
    let _ = forge_at(&fx.plugin);
    let _ = forge_at(&fx.plugin);
    let j: serde_json::Value =
        serde_json::from_slice(&std::fs::read(journal_of(&fx.plugin, o)).unwrap()).unwrap();
    assert_eq!(j["attempts"], 3, "{j}");
}

/// Test 12: a crash after the first rename (journal `moved`, served absent,
/// the old store in recovery). Meanwhile the mirror engine's materialise
/// refuses; the next `ForgeService::new` publishes from the recovery copy.
#[cfg(feature = "mirror")]
#[tokio::test]
async fn t12_crash_after_the_first_rename_resumes_and_materialise_refuses() {
    use crate::mirror::MirrorGit;
    let fx = legacy(212, Shape::Engine);
    write_record(
        &fx.plugin,
        &fx.owner,
        pre_release_record(&fx.owner).as_bytes(),
    );
    let o = &fx.owner;
    let recovery = fx
        .plugin
        .join("mirror-recovery")
        .join(o)
        .join("sample.git.1700000000");
    std::fs::create_dir_all(recovery.parent().unwrap()).unwrap();
    std::fs::rename(&fx.served, &recovery).unwrap();
    let j = journal_of(&fx.plugin, o);
    std::fs::create_dir_all(j.parent().unwrap()).unwrap();
    std::fs::write(
        &j,
        format!(r#"{{"id":"t12","ts":1700000000,"class":"mirror","state":"moved","staging":"mirror-work/staging/{o}/sample.git.gone","recovery":"mirror-recovery/{o}/sample.git.1700000000","attempts":0}}"#),
    )
    .unwrap();
    let cli = crate::mirror::GitCli::new(fx.plugin.join("repos"));
    let made = cli.materialise(o, "sample").await;
    assert!(
        made.is_err(),
        "materialise ran while a migration journal exists"
    );
    assert!(!fx.served.exists(), "materialise created the served store");
    let prepared = cli.prepare(o, "sample", true).await;
    assert!(
        prepared.is_err(),
        "prepare answered while a journal exists: {prepared:?}"
    );
    let forge = forge_at(&fx.plugin);
    assert_migrated(&fx, &forge).await;
    assert_eq!(recovery_entries(&fx.plugin, o), vec![recovery]);
}

// ---- Fix round 1 ------------------------------------------------------------
//
// One test per confirmed review finding (review-b1-security.md F1-F7,
// review-b1-code.md H1/H2/M1/L1-L7, the Codex audit items 1-6). Each was
// captured red on the tree before its fix.

use crate::migrate::test_hooks::{self, Hooks};

/// The relative recovery path of `entry` for a hand-written journal.
fn rel(plugin: &Path, entry: &Path) -> String {
    entry
        .strip_prefix(plugin)
        .unwrap()
        .to_string_lossy()
        .into_owned()
}

fn plant_journal(plugin: &Path, owner: &str, body: &str) {
    let j = journal_of(plugin, owner);
    std::fs::create_dir_all(j.parent().unwrap()).unwrap();
    std::fs::write(j, body).unwrap();
}

fn read_journal_json(plugin: &Path, owner: &str) -> serde_json::Value {
    let bytes = std::fs::read(journal_of(plugin, owner)).expect("the journal persists");
    serde_json::from_slice(&bytes).unwrap()
}

/// Held denied on every reader, and the approved content refused too: the
/// store is gated (503), not migrated.
async fn assert_gated(fx: &Legacy, forge: &crate::ForgeService) {
    let leaks = held_leaks(forge, &fx.owner, &fx.held).await;
    assert!(
        leaks.is_empty(),
        "held commit served:\n{}",
        leaks.join("\n")
    );
    let o = &fx.owner;
    let approved = get(forge, format!("/forge/{o}/sample/raw/{}/public.txt", fx.m2)).await;
    assert_eq!(
        approved.status,
        503,
        "the store is not gated: {}",
        String::from_utf8_lossy(&approved.body)
    );
}

/// Item 1 (F2): a lost-record store whose `refs/mirror/*` were removed (only
/// `hideRefs` is left) keeps `refs/misc/*` refs reaching the held commit and
/// blob. The held set is everything outside the roots, so they are dropped
/// and verification checks the held objects whatever `refs/mirror` holds.
#[tokio::test]
async fn f1_lost_record_store_without_refs_mirror_copies_roots_only() {
    let fx = legacy(231, Shape::Engine);
    let gone = git(
        &fx.served,
        &["for-each-ref", "--format=delete %(refname)", "refs/mirror"],
    );
    for line in gone.lines() {
        let r = line.trim_start_matches("delete ");
        git(&fx.served, &["update-ref", "-d", r]);
    }
    assert_eq!(git(&fx.served, &["for-each-ref", "refs/mirror"]), "");
    assert!(
        has(&fx.served, &fx.held_blob),
        "fixture: held kept by misc refs"
    );
    let forge = forge_at(&fx.plugin);
    assert_migrated(&fx, &forge).await;
    let report = report_of(&fx);
    for r in ["refs/misc/stash-held", "refs/misc/blob"] {
        assert_eq!(
            dropped_reason(&report, r).as_deref(),
            Some("outside-roots"),
            "{report}"
        );
    }
}

/// Item 1 (Codex #5): a tag git accepts but the push filter refuses (longer
/// than 1,024 bytes) points at the held commit, beside `refs/misc/stash-held`.
/// The dropped tag must not shield the held objects from the held set.
#[tokio::test]
async fn f1_a_dropped_tag_does_not_shield_held_objects() {
    let fx = legacy(232, Shape::Engine);
    let long = format!("refs/tags/{}", vec!["t".repeat(200); 6].join("/"));
    assert!(long.len() > 1024);
    git(&fx.served, &["update-ref", &long, &fx.held]);
    let forge = forge_at(&fx.plugin);
    assert_migrated(&fx, &forge).await;
    let report = report_of(&fx);
    assert_eq!(
        dropped_reason(&report, &long).as_deref(),
        Some("unsafe-name"),
        "{report}"
    );
    assert_eq!(
        dropped_reason(&report, "refs/misc/stash-held").as_deref(),
        Some("outside-roots"),
        "{report}"
    );
}

/// Item 1 (C17): a held branch upstream force-pushed away before migration.
/// Its old tip X1 is no longer under `refs/mirror`, but `refs/misc/c17`
/// still reaches it; X1's blob must not be published.
#[tokio::test]
async fn f1_force_pushed_away_held_history_is_not_copied() {
    let fx = legacy(233, Shape::Engine);
    let up = fx.home.join("up");
    git(&up, &["checkout", "--quiet", "-b", "c17", &fx.m2]);
    let x1 = commit(&up, &[("c17.txt", "b1-c17-secret\n")], "b1 c17 old tip");
    let x1_blob = git(&up, &["rev-parse", "HEAD:c17.txt"]);
    git(&up, &["checkout", "--quiet", "main"]);
    git(
        &fx.served,
        &[
            "fetch",
            "--quiet",
            "--no-tags",
            up.to_str().unwrap(),
            "+refs/heads/c17:refs/mirror/c17",
        ],
    );
    git(&fx.served, &["update-ref", "refs/misc/c17", &x1]);
    // Upstream force-pushes c17 back to the approved tip.
    git(&fx.served, &["update-ref", "refs/mirror/c17", &fx.m2]);
    git(&fx.served, &["repack", "-a", "-d", "-q"]);
    for e in std::fs::read_dir(fx.served.join("objects/pack"))
        .unwrap()
        .flatten()
    {
        let p = e.path();
        if p.extension().is_some_and(|x| x == "pack") {
            std::fs::write(p.with_extension("keep"), b"b1 fixture\n").unwrap();
        }
    }
    let forge = forge_at(&fx.plugin);
    let o = &fx.owner;
    let raw = get(&forge, format!("/forge/{o}/sample/raw/{x1}/c17.txt")).await;
    assert_eq!(raw.status, 404, "{}", String::from_utf8_lossy(&raw.body));
    assert!(!has(&fx.served, &x1), "the force-pushed-away tip is served");
    assert!(!has(&fx.served, &x1_blob), "its blob is served");
    assert_migrated(&fx, &forge).await;
    assert_eq!(
        dropped_reason(&report_of(&fx), "refs/misc/c17").as_deref(),
        Some("outside-roots")
    );
}

/// Item 2 (F1, M1, Codex #2): a detection check that fails (here the
/// alternates `stat`, `objects/info` at mode 000) gates the store behind a
/// `detection-error` journal instead of leaving it served. Once the check
/// succeeds and finds the store clean, that journal (and only that kind) is
/// removed.
#[tokio::test]
async fn f2_a_detection_error_gates_and_a_clean_recheck_ungates() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path();
    let plugin = home.join("plugin");
    let owner = owner_of(234);
    let served = plugin.join("repos").join(&owner).join("sample.git");
    let sha = bare_with_commit(home, &served, "b1-undetected-bytes\n");
    // Control: another store's `failed` journal for another reason is kept.
    let other = owner_of(235);
    bare_with_commit(
        home,
        &plugin.join("repos").join(&other).join("sample.git"),
        "x\n",
    );
    let kept = format!(
        r#"{{"id":"keep","ts":1,"class":"mirror","state":"failed","recovery":"mirror-recovery/{other}/sample.git.1","attempts":3,"reason":"push into staging failed"}}"#
    );
    plant_journal(&plugin, &other, &kept);
    let info = served.join("objects").join("info");
    std::fs::create_dir_all(&info).unwrap();
    std::fs::set_permissions(&info, std::fs::Permissions::from_mode(0o000)).unwrap();
    assert!(
        std::fs::symlink_metadata(info.join("alternates"))
            .is_err_and(|e| e.kind() == std::io::ErrorKind::PermissionDenied),
        "precondition: mode 000 must block the alternates check (not running as root?)"
    );
    let forge = forge_at(&plugin);
    let read = get(&forge, format!("/forge/{owner}/sample/raw/{sha}/f.txt")).await;
    let gated = read.status;
    let journal = std::fs::read(journal_of(&plugin, &owner));
    std::fs::set_permissions(&info, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        gated,
        503,
        "a store detection could not examine is served: {}",
        String::from_utf8_lossy(&read.body)
    );
    let j: serde_json::Value = serde_json::from_slice(&journal.expect("a gate journal")).unwrap();
    assert_eq!(j["state"], "failed", "{j}");
    assert_eq!(j["attempts"], 0, "{j}");
    let reason = j["reason"].as_str().unwrap_or("");
    assert!(reason.starts_with("detection-error"), "{j}");
    assert!(
        !reason.contains(plugin.to_str().unwrap()),
        "unredacted: {j}"
    );
    // Next boot: the check succeeds, the store is a plain owner store.
    let forge = forge_at(&plugin);
    assert!(
        !journal_of(&plugin, &owner).exists(),
        "the detection-error journal was not removed"
    );
    let read = get(&forge, format!("/forge/{owner}/sample/raw/{sha}/f.txt")).await;
    assert_eq!(read.status, 200, "{}", String::from_utf8_lossy(&read.body));
    assert!(!served.join(MARKER).exists(), "a plain store was rebuilt");
    assert_eq!(
        std::fs::read_to_string(journal_of(&plugin, &other)).unwrap(),
        kept,
        "another kind of journal was touched"
    );
}

/// Item 2: when the migration thread panics (or its runtime cannot be
/// built), every store under a 64-hex owner is refused, marked or not (fix
/// round 2, item 2); other owners are not.
#[tokio::test]
async fn f2_a_panicked_migration_gates_unmarked_mirror_class_stores() {
    let fx = legacy(236, Shape::Engine);
    let marked = owner_of(237);
    let marked_dir = fx.plugin.join("repos").join(&marked).join("sample.git");
    let marked_sha = bare_with_commit(&fx.home, &marked_dir, "b1-marked\n");
    std::fs::write(marked_dir.join(MARKER), format!("{MARKER}\n")).unwrap();
    let plain_sha = bare_with_commit(
        &fx.home,
        &fx.plugin.join("repos/bob/plain.git"),
        "b1-plain\n",
    );
    test_hooks::set(
        &fx.plugin,
        Hooks {
            panic_at_boot: true,
            ..Hooks::default()
        },
    );
    let forge = forge_at(&fx.plugin);
    test_hooks::clear(&fx.plugin);
    assert_gated(&fx, &forge).await;
    let ok = get(
        &forge,
        format!("/forge/{marked}/sample/raw/{marked_sha}/f.txt"),
    )
    .await;
    // Fix round 2, item 2: an incomplete pass refuses marked stores under a
    // 64-hex owner too.
    assert_eq!(ok.status, 503, "a marked mirror-class store is not refused");
    let ok = get(&forge, format!("/forge/bob/plain/raw/{plain_sha}/f.txt")).await;
    assert_eq!(ok.status, 200, "control: a non-mirror owner");
}

/// Item 3 (L1, Codex #1): a journal that is a symlink, dangling or pointing
/// at a `published` journal, gates every reader; a boot leaves it in place.
#[tokio::test]
async fn f3_a_symlinked_journal_gates() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path();
    let plugin = home.join("plugin");
    let owner = owner_of(238);
    let served = plugin.join("repos").join(&owner).join("sample.git");
    let sha = bare_with_commit(home, &served, "b1-symlink\n");
    std::fs::write(served.join(MARKER), format!("{MARKER}\n")).unwrap();
    let forge = forge_at(&plugin);
    let path = format!("/forge/{owner}/sample/raw/{sha}/f.txt");
    assert_eq!(get(&forge, path.clone()).await.status, 200, "control");
    let published = home.join("published.json");
    std::fs::write(
        &published,
        format!(r#"{{"id":"x","ts":1,"class":"mirror","state":"published","recovery":"mirror-recovery/{owner}/sample.git.1","attempts":0}}"#),
    )
    .unwrap();
    let j = journal_of(&plugin, &owner);
    std::fs::create_dir_all(j.parent().unwrap()).unwrap();
    for target in [home.join("nowhere.json"), published] {
        let _ = std::fs::remove_file(&j);
        std::os::unix::fs::symlink(&target, &j).unwrap();
        let r = get(&forge, path.clone()).await;
        assert_eq!(
            r.status,
            503,
            "a journal symlink to {} opened the gate",
            target.display()
        );
        let again = forge_at(&plugin);
        assert!(
            std::fs::symlink_metadata(&j).is_ok_and(|m| m.file_type().is_symlink()),
            "a boot removed the symlinked journal ({})",
            target.display()
        );
        assert_eq!(get(&again, path.clone()).await.status, 503);
    }
}

/// Item 3 (Codex #3): a journal whose `recovery` leaves `mirror-recovery/`
/// fails the migration closed; nothing is written outside it.
#[tokio::test]
async fn f3_a_journal_recovery_outside_mirror_recovery_fails_closed() {
    let fx = legacy(239, Shape::Engine);
    let o = &fx.owner;
    plant_journal(
        &fx.plugin,
        o,
        &format!(
            r#"{{"id":"esc","ts":1,"class":"mirror","state":"building","recovery":"mirror-recovery/{o}/../../escape/sample.git.1","attempts":0}}"#
        ),
    );
    let forge = forge_at(&fx.plugin);
    assert!(
        !fx.plugin.join("escape").exists(),
        "the migration wrote outside mirror-recovery/"
    );
    assert_gated(&fx, &forge).await;
    assert!(has(&fx.served, &fx.held_blob), "the old store was moved");
}

/// Item 4 (Codex #4, L6, F4): smart HTTP accepts exactly
/// `/<owner>/<name>[.git]/<suffix>`. A nested bare repository is not
/// fetchable, and the suffix-less form opens `<name>.git`, the directory the
/// gate checks, never a bare `repos/<owner>/<name>`.
#[tokio::test]
async fn f4_smart_http_accepts_one_path_shape() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path();
    let plugin = home.join("plugin");
    let nested = bare_with_commit(home, &plugin.join("repos/bob/dir/x"), "b1-nested\n");
    let nested_git = bare_with_commit(home, &plugin.join("repos/bob/dir/y.git"), "b1-nested-git\n");
    let bare = bare_with_commit(home, &plugin.join("repos/bob/plain"), "b1-suffixless\n");
    let ok = bare_with_commit(home, &plugin.join("repos/bob/real.git"), "b1-real\n");
    let forge = forge_with_backend(&plugin);
    let adv = |path: &str| req("GET", path, "service=git-upload-pack");
    let answer = |r: Result<crate::ForgeResponse, crate::ForgeError>| match r {
        Ok(resp) => (
            resp.status,
            String::from_utf8_lossy(&resp.body).into_owned(),
        ),
        Err(e) => (e.status_code(), e.to_string()),
    };
    for (path, sha) in [
        ("/forge/bob/dir/x/info/refs", &nested),
        ("/forge/bob/dir/y.git/info/refs", &nested_git),
        ("/forge/bob/plain/info/refs", &bare),
        ("/forge/bob/.dir/x.git/info/refs", &nested),
        ("/forge/bob/dir%2Fx/info/refs", &nested),
    ] {
        let (status, body) = answer(forge.handle(adv(path), crate::ForgeAgent::Anonymous).await);
        assert!(
            status == 404 || (status == 400 && path.contains('%')),
            "{path} -> {status}: {body}"
        );
        assert!(
            !body.contains(sha.as_str()),
            "{path} advertised {sha}: {body}"
        );
    }
    for path in ["/forge/bob/real.git/info/refs", "/forge/bob/real/info/refs"] {
        let (status, body) = answer(forge.handle(adv(path), crate::ForgeAgent::Anonymous).await);
        assert_eq!(status, 200, "control {path}: {body}");
        assert!(body.contains(&ok), "control {path}: {body}");
    }
}

/// Run a real migration of a record-bearing fixture, then rewind it to the
/// state a crash after the second rename leaves: the journal back at
/// `state` (with `moved`), the record flagged again. Returns the report's
/// bytes and the recovery entry.
fn rewind_after_second_rename(fx: &Legacy, state: &str, moved: bool) -> (Vec<u8>, PathBuf) {
    let entry = recovery_entries(&fx.plugin, &fx.owner).remove(0);
    let report = std::fs::read(sibling(&entry, ".migration.json")).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&report).unwrap();
    let id = match v["id"].as_str() {
        Some(id) => id.to_string(),
        None => {
            // The pre-fix tree writes no id: plant one in both places.
            std::fs::write(fx.served.join(MIGRATION_ID), "b1crashid\n").unwrap();
            "b1crashid".to_string()
        }
    };
    let o = &fx.owner;
    plant_journal(
        &fx.plugin,
        o,
        &format!(
            r#"{{"id":"{id}","ts":1,"class":"mirror","state":"{state}","moved":{moved},"staging":"mirror-work/staging/{o}/sample.git.0123456789abcdef0123456789abcdef","recovery":"{}","attempts":1}}"#,
            rel(&fx.plugin, &entry)
        ),
    );
    write_record(&fx.plugin, o, pre_release_record(o).as_bytes());
    (report, entry)
}

/// Item 5 (H1, H2, Codex #3): a crash after `rename(staging -> served)`,
/// on the normal path (`moved`) and on the resumed path (`verified` after a
/// resume, and `verified` when the `moved` write was lost). The next boot
/// sees its own store in place (the migration id matches), publishes it and
/// finishes, without rebuilding or touching the report.
#[tokio::test]
async fn f5_a_crash_after_the_second_rename_is_finished_not_rebuilt() {
    for (seed, state, moved) in [
        (240u8, "moved", true),
        (241, "verified", true),
        (242, "verified", false),
    ] {
        let fx = legacy(seed, Shape::Engine);
        write_record(
            &fx.plugin,
            &fx.owner,
            pre_release_record(&fx.owner).as_bytes(),
        );
        drop(forge_at(&fx.plugin));
        let (report, entry) = rewind_after_second_rename(&fx, state, moved);
        let forge = forge_at(&fx.plugin);
        assert!(
            !journal_of(&fx.plugin, &fx.owner).exists(),
            "{state}/{moved}: journal left: {}",
            std::fs::read_to_string(journal_of(&fx.plugin, &fx.owner)).unwrap_or_default()
        );
        assert_eq!(
            std::fs::read(sibling(&entry, ".migration.json")).unwrap(),
            report,
            "{state}/{moved}: the report was rewritten"
        );
        assert_eq!(recovery_entries(&fx.plugin, &fx.owner), vec![entry]);
        let rec: serde_json::Value =
            serde_json::from_slice(&std::fs::read(record_path(&fx.plugin, &fx.owner)).unwrap())
                .unwrap();
        assert!(
            rec.get("awaitsMigration").is_none(),
            "{state}/{moved}: flag kept: {rec}"
        );
        assert_migrated(&fx, &forge).await;
    }
}

/// Item 5 (Codex #5): a stale report beside a substituted, marked, flagged
/// store does not finish it: the report names another migration, so the
/// store is rebuilt and its held objects are not served.
#[tokio::test]
async fn f5_a_stale_report_does_not_finish_a_substituted_store() {
    let fx = legacy(243, Shape::Engine);
    let o = &fx.owner;
    write_record(&fx.plugin, o, pre_release_record(o).as_bytes());
    std::fs::write(fx.served.join(MARKER), format!("{MARKER}\n")).unwrap();
    std::fs::write(fx.served.join(MIGRATION_ID), "someoneelse\n").unwrap();
    let dir = fx.plugin.join("mirror-recovery").join(o);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("sample.git.1600000000.migration.json"),
        format!(r#"{{"id":"stale","owner":"{o}","name":"sample","class":"mirror"}}"#),
    )
    .unwrap();
    let forge = forge_at(&fx.plugin);
    let leaks = held_leaks(&forge, o, &fx.held).await;
    assert!(
        leaks.is_empty(),
        "held commit served:\n{}",
        leaks.join("\n")
    );
    assert!(
        !has(&fx.served, &fx.held_blob),
        "the substituted store was kept"
    );
}

/// Item 6 (F3), child half: crash (abort) mid-build.
const F6_CHILD: &str = "SOLID_FORGE_B1_F6_PLUGIN";

/// Item 6 (F3): an attempt counts when it starts. Three crashes mid-build
/// use up the budget, and the fourth boot gives up with the store gated.
#[test]
fn f6_three_crashes_mid_build_then_the_boot_gives_up() {
    if let Ok(dir) = std::env::var(F6_CHILD) {
        test_hooks::set(
            Path::new(&dir),
            Hooks {
                abort_in_build: true,
                ..Hooks::default()
            },
        );
        let _ = forge_at(Path::new(&dir));
        return;
    }
    let fx = legacy(244, Shape::Engine);
    let me = std::env::current_exe().unwrap();
    for n in 1..=3 {
        let st = Command::new(&me)
            .args([
                "--exact",
                "migrate_tests::f6_three_crashes_mid_build_then_the_boot_gives_up",
                "--nocapture",
            ])
            .env(F6_CHILD, &fx.plugin)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(!st.success(), "crash {n}: the child did not crash");
        let j = read_journal_json(&fx.plugin, &fx.owner);
        assert_eq!(j["state"], "building", "crash {n}: {j}");
    }
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let forge = forge_at(&fx.plugin);
        assert!(
            journal_of(&fx.plugin, &fx.owner).exists(),
            "the fourth boot migrated instead of giving up"
        );
        let j = read_journal_json(&fx.plugin, &fx.owner);
        assert_eq!(j["attempts"], 3, "{j}");
        assert_gated(&fx, &forge).await;
        assert!(!fx.served.join(MARKER).exists());
    });
}

/// Item 7 (F7, L3, Codex #6): a lock another process holds is waited for
/// only up to the deadline; then the store is gated (decision 21) and
/// skipped, and boot goes on. Released, the next boot migrates it.
#[test]
fn f7_a_held_lock_times_out_and_gates() {
    let fx = legacy(245, Shape::Engine);
    let lock = crate::migrate::lock_path(&fx.plugin, &fx.owner, "sample").unwrap();
    std::fs::create_dir_all(lock.parent().unwrap()).unwrap();
    let held = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&lock)
        .unwrap();
    held.lock().unwrap();
    test_hooks::set(
        &fx.plugin,
        Hooks {
            lock_wait: Some(std::time::Duration::from_millis(300)),
            ..Hooks::default()
        },
    );
    let (tx, rx) = std::sync::mpsc::channel();
    let plugin = fx.plugin.clone();
    std::thread::spawn(move || {
        let _ = tx.send(forge_at(&plugin));
    });
    let got = rx.recv_timeout(std::time::Duration::from_secs(30));
    test_hooks::clear(&fx.plugin);
    let forge = got.expect("ForgeService::new waited on the lock past its deadline");
    let j = read_journal_json(&fx.plugin, &fx.owner);
    assert_eq!(j["state"], "failed", "{j}");
    assert!(j["reason"].as_str().unwrap_or("").contains("lock"), "{j}");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(assert_gated(&fx, &forge));
    drop(held);
    rt.block_on(async {
        let forge = forge_at(&fx.plugin);
        assert_migrated(&fx, &forge).await;
    });
}

/// Item 9 (L4, Codex): when the store budget runs out, every process in
/// the build's process groups is killed, not only the direct child.
#[tokio::test]
async fn f9_a_budget_timeout_kills_the_whole_process_group() {
    let token = "41.4142135";
    let fx = legacy(246, Shape::Engine);
    test_hooks::set(
        &fx.plugin,
        Hooks {
            store_budget: Some(std::time::Duration::from_secs(2)),
            slow_child: Some(token.into()),
            ..Hooks::default()
        },
    );
    let forge = forge_at(&fx.plugin);
    test_hooks::clear(&fx.plugin);
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    let left = Command::new("pgrep")
        .args(["-f", &format!("sleep {token}")])
        .output()
        .unwrap();
    let survivors = String::from_utf8_lossy(&left.stdout).trim().to_string();
    let _ = Command::new("pkill")
        .args(["-f", &format!("sleep {token}")])
        .status();
    assert!(
        survivors.is_empty(),
        "orphaned helpers survived: {survivors}"
    );
    let j = read_journal_json(&fx.plugin, &fx.owner);
    assert!(j["reason"].as_str().unwrap_or("").contains("budget"), "{j}");
    assert_gated(&fx, &forge).await;
}

/// Item 10 (Codex #2): the push into staging runs under the size cap. A
/// staging store past it is killed, and the migration fails closed.
#[tokio::test]
async fn f10_a_staging_store_past_the_size_cap_fails_closed() {
    let fx = legacy(247, Shape::Engine);
    test_hooks::set(
        &fx.plugin,
        Hooks {
            size_cap: Some(1),
            ..Hooks::default()
        },
    );
    let forge = forge_at(&fx.plugin);
    test_hooks::clear(&fx.plugin);
    assert!(
        journal_of(&fx.plugin, &fx.owner).exists(),
        "the store was migrated past the size cap"
    );
    let j = read_journal_json(&fx.plugin, &fx.owner);
    assert_eq!(j["state"], "failed", "{j}");
    assert!(
        j["reason"].as_str().unwrap_or("").contains("size cap"),
        "{j}"
    );
    assert_gated(&fx, &forge).await;
}

/// Item 11 (L5): a ref whose name is not UTF-8 is dropped as `unsafe-name`
/// and reported; it is never copied under a lossy name.
#[tokio::test]
async fn f11_a_non_utf8_ref_is_dropped_not_renamed() {
    use std::os::unix::ffi::OsStrExt;
    let fx = legacy(248, Shape::Engine);
    let name = std::ffi::OsStr::from_bytes(b"refs/misc/\xff\xfe");
    let st = Command::new("git")
        .arg("update-ref")
        .arg(name)
        .arg(&fx.m2)
        .current_dir(&fx.served)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .status()
        .unwrap();
    assert!(st.success());
    let forge = forge_at(&fx.plugin);
    let refs = Command::new("git")
        .args(["for-each-ref", "--format=%(refname)"])
        .current_dir(&fx.served)
        .output()
        .unwrap()
        .stdout;
    assert!(
        std::str::from_utf8(&refs).is_ok_and(|s| !s.contains('\u{fffd}')),
        "a non-UTF-8 ref was copied: {}",
        String::from_utf8_lossy(&refs)
    );
    assert_migrated(&fx, &forge).await;
    let report = report_of(&fx);
    let lossy = String::from_utf8_lossy(b"refs/misc/\xff\xfe").into_owned();
    assert_eq!(
        dropped_reason(&report, &lossy).as_deref(),
        Some("unsafe-name"),
        "{report}"
    );
}

/// Item 12 (F6): a fork onto a name with a migration journal is refused
/// (503); it would otherwise land in the gap between the two renames.
#[tokio::test]
async fn f12_a_fork_onto_a_journalled_name_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path();
    let plugin = home.join("plugin");
    bare_with_commit(home, &plugin.join("repos/alice/src.git"), "b1-src\n");
    let caller = owner_of(249);
    let forge = forge_at(&plugin);
    plant_journal(
        &plugin,
        &caller,
        &format!(
            r#"{{"id":"f","ts":1,"class":"mirror","state":"moved","moved":true,"recovery":"mirror-recovery/{caller}/sample.git.1","attempts":0}}"#
        ),
    );
    let mut r = req("POST", "/forge/api/repos/alice/src/fork", "");
    r.raw_body = bytes::Bytes::from_static(br#"{"name":"sample"}"#);
    let got = forge
        .handle(
            r,
            crate::ForgeAgent::Nostr {
                pubkey_hex: caller.clone(),
            },
        )
        .await;
    let status = got.map_or_else(|e| e.status_code(), |r| r.status);
    assert_eq!(status, 503, "a fork landed on a journalled name");
    assert!(!plugin
        .join("repos")
        .join(&caller)
        .join("sample.git")
        .exists());
}

/// Item 1 (advisor review of fix round 1): an owner-planted
/// `refs/replace/<m2>` makes `rev-list` walk a commit whose tree adds the
/// held blob, while a push sends the originals. Replacements must not widen
/// the roots' closure, or `refs/misc/blob` would pass the filter and both
/// verify checks.
#[tokio::test]
async fn f1_a_replace_ref_does_not_widen_the_roots() {
    let fx = legacy(250, Shape::Engine);
    let m2_tree = git(&fx.served, &["rev-parse", &format!("{}^{{tree}}", fx.m2)]);
    let listing = format!(
        "040000 tree {m2_tree}\tsub\n100644 blob {}\theld.txt\n",
        fx.held_blob
    );
    let mut child = Command::new("git")
        .args(["mktree"])
        .current_dir(&fx.served)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    {
        use std::io::Write;
        child
            .stdin
            .take()
            .unwrap()
            .write_all(listing.as_bytes())
            .unwrap();
    }
    let tree = String::from_utf8_lossy(&child.wait_with_output().unwrap().stdout)
        .trim()
        .to_string();
    let fake = git(
        &fx.served,
        &["commit-tree", &tree, "-p", &fx.m1, "-m", "b1 replacement"],
    );
    git(
        &fx.served,
        &["update-ref", &format!("refs/replace/{}", fx.m2), &fake],
    );
    let forge = forge_at(&fx.plugin);
    assert!(
        !has(&fx.served, &fx.held_blob),
        "a replacement smuggled the held blob into the rebuilt store"
    );
    assert_migrated(&fx, &forge).await;
    let report = report_of(&fx);
    assert_eq!(
        dropped_reason(&report, "refs/misc/blob").as_deref(),
        Some("outside-roots"),
        "{report}"
    );
}

/// Item 3 (Codex #1, second half): a regular-file journal reading
/// `published` beside a store that is not this migration's (no matching
/// migration id) is never finished; the store stays gated.
#[tokio::test]
async fn f3_a_forged_published_journal_does_not_open_a_store() {
    let fx = legacy(251, Shape::Engine);
    let o = &fx.owner;
    plant_journal(
        &fx.plugin,
        o,
        &format!(
            r#"{{"id":"forged","ts":1,"class":"mirror","state":"published","recovery":"mirror-recovery/{o}/sample.git.1","attempts":0}}"#
        ),
    );
    let forge = forge_at(&fx.plugin);
    assert_gated(&fx, &forge).await;
    assert!(
        journal_of(&fx.plugin, o).exists(),
        "the forged journal was finished"
    );
}

/// Item 1/2 (advisor review): a served store reached through a symlink
/// (`repos/<owner>/<name>.git -> elsewhere`, as an operator moving stores to
/// another disk makes) is listed and served, so detection must examine it
/// too.
#[tokio::test]
async fn f2_a_symlinked_served_store_is_detected() {
    let fx = legacy(252, Shape::Engine);
    let elsewhere = fx.home.join("disk2").join("sample.git");
    std::fs::create_dir_all(elsewhere.parent().unwrap()).unwrap();
    std::fs::rename(&fx.served, &elsewhere).unwrap();
    std::os::unix::fs::symlink(&elsewhere, &fx.served).unwrap();
    let forge = forge_at(&fx.plugin);
    let leaks = held_leaks(&forge, &fx.owner, &fx.held).await;
    assert!(
        leaks.is_empty(),
        "held commit served:\n{}",
        leaks.join("\n")
    );
    assert_migrated(&fx, &forge).await;
}

// ---- Fix round 2 ------------------------------------------------------------
//
// One test per remaining fail-open path (b1-fix2-brief.md items 1-6), each
// captured red on the fix-round-1 tree.

/// Make `dir` keep the commits grafted or planted since the fixture was built
/// in a `.keep` pack (C15-hard).
fn keep_packs(dir: &Path) {
    git(dir, &["repack", "-a", "-d", "-q"]);
    for e in std::fs::read_dir(dir.join("objects/pack"))
        .unwrap()
        .flatten()
    {
        let p = e.path();
        if p.extension().is_some_and(|x| x == "pack") && !p.with_extension("keep").exists() {
            std::fs::write(p.with_extension("keep"), b"b1 fixture\n").unwrap();
        }
    }
}

/// Item 1 (Codex High 1, security N2, code N1): every journal gates,
/// `published` included. A regular `published` journal at `attempts: 3` with
/// no matching migration id, beside a lost-record legacy store, keeps it
/// refused across boots.
#[tokio::test]
async fn g1_a_published_journal_gates_across_boots() {
    let fx = legacy(170, Shape::Engine);
    let o = &fx.owner;
    plant_journal(
        &fx.plugin,
        o,
        &format!(
            r#"{{"id":"stale","ts":1,"class":"mirror","state":"published","moved":true,"recovery":"mirror-recovery/{o}/sample.git.1","attempts":3}}"#
        ),
    );
    for boot in 1..=2 {
        let forge = forge_at(&fx.plugin);
        let leaks = held_leaks(&forge, o, &fx.held).await;
        assert!(
            leaks.is_empty(),
            "boot {boot}: held commit served:\n{}",
            leaks.join("\n")
        );
        assert_gated(&fx, &forge).await;
    }
}

/// Item 2 (Codex High 2): while the pass is incomplete, a marked store under a
/// 64-hex owner is refused too. Here a marked, flagged store with no bound
/// report cannot be journalled (the migrations directory is read-only).
#[tokio::test]
async fn g2_an_incomplete_pass_gates_a_marked_store() {
    use std::os::unix::fs::PermissionsExt;
    let fx = legacy(171, Shape::Engine);
    let o = &fx.owner;
    write_record(&fx.plugin, o, pre_release_record(o).as_bytes());
    std::fs::write(fx.served.join(MARKER), format!("{MARKER}\n")).unwrap();
    let migrations = fx.plugin.join("mirror-work").join("migrations");
    std::fs::create_dir_all(&migrations).unwrap();
    std::fs::set_permissions(&migrations, std::fs::Permissions::from_mode(0o555)).unwrap();
    assert!(
        std::fs::create_dir(migrations.join("probe"))
            .is_err_and(|e| e.kind() == std::io::ErrorKind::PermissionDenied),
        "precondition: the migrations directory must be read-only (not running as root?)"
    );
    let forge = forge_at(&fx.plugin);
    let leaks = held_leaks(&forge, o, &fx.held).await;
    let approved = get(
        &forge,
        format!("/forge/{o}/sample/raw/{}/public.txt", fx.m2),
    )
    .await;
    std::fs::set_permissions(&migrations, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(
        forge.migration_incomplete,
        "the pass did not report incomplete"
    );
    assert!(
        leaks.is_empty(),
        "held commit served:\n{}",
        leaks.join("\n")
    );
    assert_eq!(approved.status, 503, "the marked store is not gated");
}

/// Item 3 (security N1): an owner directory that can be searched but not
/// listed makes the pass incomplete; that owner's legacy store is refused.
#[tokio::test]
async fn g3_an_unlistable_owner_makes_the_pass_incomplete() {
    use std::os::unix::fs::PermissionsExt;
    let fx = legacy(172, Shape::Engine);
    let owner_dir = fx.served.parent().unwrap().to_path_buf();
    std::fs::set_permissions(&owner_dir, std::fs::Permissions::from_mode(0o311)).unwrap();
    let listable = std::fs::read_dir(&owner_dir);
    let reachable = std::fs::metadata(&fx.served).is_ok_and(|m| m.is_dir());
    let forge = forge_at(&fx.plugin);
    let leaks = held_leaks(&forge, &fx.owner, &fx.held).await;
    let approved = get(
        &forge,
        format!("/forge/{}/sample/raw/{}/public.txt", fx.owner, fx.m2),
    )
    .await;
    std::fs::set_permissions(&owner_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(
        listable.is_err_and(|e| e.kind() == std::io::ErrorKind::PermissionDenied) && reachable,
        "precondition: the owner directory must be searchable but not listable"
    );
    assert!(
        leaks.is_empty(),
        "held commit served:\n{}",
        leaks.join("\n")
    );
    assert!(
        forge.migration_incomplete,
        "the pass did not report incomplete"
    );
    assert_eq!(approved.status, 503, "the unlisted store is not gated");
}

/// Item 4 (Codex Medium 5): a detection-error journal is removed only when
/// detection examined every signal and found them negative. A boot on which
/// the store-directory probe itself fails leaves it.
#[tokio::test]
async fn g4_a_failing_store_probe_leaves_the_detection_error_journal() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path();
    let plugin = home.join("plugin");
    let owner = owner_of(173);
    let served = plugin.join("repos").join(&owner).join("sample.git");
    bare_with_commit(home, &served, "b1-probe\n");
    let body = format!(
        r#"{{"id":"probe","ts":1,"class":"mirror","state":"failed","recovery":"mirror-recovery/{owner}/sample.git.1","attempts":0,"reason":"detection-error: the alternates check failed"}}"#
    );
    plant_journal(&plugin, &owner, &body);
    let owner_dir = served.parent().unwrap().to_path_buf();
    std::fs::set_permissions(&owner_dir, std::fs::Permissions::from_mode(0o000)).unwrap();
    let probe = std::fs::metadata(&served);
    drop(forge_at(&plugin));
    std::fs::set_permissions(&owner_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(
        probe.is_err_and(|e| e.kind() == std::io::ErrorKind::PermissionDenied),
        "precondition: the store probe must fail with EACCES"
    );
    assert!(
        journal_of(&plugin, &owner).exists(),
        "a detection-error journal was removed without a clean examination"
    );
}

/// Item 5 (security N3): a legacy `info/grafts` line grafting held history
/// onto an approved commit neither widens the roots' closure nor makes the
/// push send the held objects.
#[tokio::test]
async fn g5_grafts_do_not_widen_the_roots() {
    let fx = legacy(174, Shape::Engine);
    let work = fx.home.join("graft-work");
    std::fs::create_dir_all(&work).unwrap();
    git(&work, &["init", "--quiet", "-b", "g"]);
    let g = commit(&work, &[("graft.txt", "b1-graft-secret\n")], "b1 grafted");
    let g_blob = git(&work, &["rev-parse", "HEAD:graft.txt"]);
    git(
        &fx.served,
        &[
            "fetch",
            "--quiet",
            "--no-tags",
            work.to_str().unwrap(),
            "+refs/heads/g:refs/misc/g5",
        ],
    );
    keep_packs(&fx.served);
    std::fs::create_dir_all(fx.served.join("info")).unwrap();
    std::fs::write(
        fx.served.join("info").join("grafts"),
        format!("{} {} {g}\n", fx.m2, fx.m1),
    )
    .unwrap();
    let forge = forge_at(&fx.plugin);
    assert!(
        !has(&fx.served, &g_blob),
        "a graft smuggled held history into the rebuilt store"
    );
    assert_migrated(&fx, &forge).await;
    assert_eq!(
        dropped_reason(&report_of(&fx), "refs/misc/g5").as_deref(),
        Some("outside-roots")
    );
}

/// Item 6 (code N3): `refs/replace/*` is never copied, even when its target
/// reaches nothing held; its name would disclose a held id.
#[tokio::test]
async fn g6_replace_refs_are_never_copied() {
    let fx = legacy(175, Shape::Engine);
    let r = format!("refs/replace/{}", fx.held);
    git(&fx.served, &["update-ref", &r, &fx.m2]);
    let forge = forge_at(&fx.plugin);
    let refs = refs_of(&fx.served);
    assert!(
        !refs.contains("refs/replace/"),
        "a replace ref was copied: {refs}"
    );
    assert_eq!(
        dropped_reason(&report_of(&fx), &r).as_deref(),
        Some("outside-roots")
    );
    assert_migrated(&fx, &forge).await;
}

// ---- Fix round 3 ------------------------------------------------------------

/// Fix 3, item 1 (Codex High 1): a lost-record legacy store whose
/// `mirror-recovery/<owner>` directory cannot be searched. The recovery
/// probe fails after detection chose to rebuild; the journal must already be
/// on disk then (or the pass must report incomplete), so the store is
/// refused.
#[tokio::test]
async fn h1_a_recovery_probe_error_still_gates_the_store() {
    use std::os::unix::fs::PermissionsExt;
    let fx = legacy(180, Shape::Engine);
    let recovery_owner = fx.plugin.join("mirror-recovery").join(&fx.owner);
    std::fs::create_dir_all(&recovery_owner).unwrap();
    std::fs::set_permissions(&recovery_owner, std::fs::Permissions::from_mode(0o000)).unwrap();
    let probe = std::fs::symlink_metadata(recovery_owner.join("sample.git.1"));
    let forge = forge_at(&fx.plugin);
    let leaks = held_leaks(&forge, &fx.owner, &fx.held).await;
    let approved = get(
        &forge,
        format!("/forge/{}/sample/raw/{}/public.txt", fx.owner, fx.m2),
    )
    .await;
    std::fs::set_permissions(&recovery_owner, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(
        probe.is_err_and(|e| e.kind() == std::io::ErrorKind::PermissionDenied),
        "precondition: the recovery probe must fail with EACCES"
    );
    assert!(
        journal_of(&fx.plugin, &fx.owner).exists() || forge.migration_incomplete,
        "no journal and a complete pass: nothing gates the store"
    );
    assert!(
        leaks.is_empty(),
        "held commit served:\n{}",
        leaks.join("\n")
    );
    assert_eq!(approved.status, 503, "the store is not gated");
}

/// Fix 3, item 2 (Codex Medium 2): a push that finishes before the size
/// watcher measures anything is still checked against the cap once it has
/// completed, and the migration fails closed.
#[tokio::test]
async fn h2_a_fast_push_past_the_cap_is_caught_by_the_final_check() {
    let fx = legacy(181, Shape::Engine);
    test_hooks::set(
        &fx.plugin,
        Hooks {
            size_cap: Some(1),
            size_poll: Some(std::time::Duration::from_secs(3600)),
            ..Hooks::default()
        },
    );
    let forge = forge_at(&fx.plugin);
    test_hooks::clear(&fx.plugin);
    assert!(
        journal_of(&fx.plugin, &fx.owner).exists(),
        "the store was migrated past the size cap"
    );
    let j = read_journal_json(&fx.plugin, &fx.owner);
    assert_eq!(j["state"], "failed", "{j}");
    assert!(
        j["reason"].as_str().unwrap_or("").contains("size cap"),
        "{j}"
    );
    assert_gated(&fx, &forge).await;
}

#[path = "migrate_fork_tests.rs"]
mod fork;
