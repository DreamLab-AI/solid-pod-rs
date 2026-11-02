//! Tests for the fork sweep of the boot migration (SP-GIT-02 Commit B2).
//!
//! A child of `migrate_tests`, so it shares its fixtures. Every fork here is
//! made the way production makes one (`forks::build_fork_at`, a
//! `clone --local --bare` that hardlinks the parent's packs), and that
//! hardlink is asserted as a precondition (control C15: a delete-plus-gc
//! implementation goes red on a hardlinked fork).

use super::*;

/// Make `<fork_owner>/sample` a fork of `<src_owner>/<src_name>` with the
/// production fork builder, under a `.fork-*.tmp` name, then renamed into
/// place as `h_api_fork` does.
async fn make_fork(plugin: &Path, src_owner: &str, fork_owner: &str) -> PathBuf {
    let repos = plugin.join("repos");
    let src = repos.join(src_owner).join("sample.git");
    let owner_dir = repos.join(fork_owner);
    std::fs::create_dir_all(&owner_dir).unwrap();
    let tmp = owner_dir.join(format!(".fork-{}.tmp", uuid::Uuid::new_v4()));
    crate::forks::build_fork_at(&repos, &src, &tmp, src_owner, "sample")
        .await
        .expect("the fork builds");
    let dest = owner_dir.join("sample.git");
    std::fs::rename(&tmp, &dest).unwrap();
    dest
}

/// Precondition (C15): the fork shares at least one pack file, by inode,
/// with `parent`.
fn assert_hardlinked(parent: &Path, fork: &Path) {
    use std::os::unix::fs::MetadataExt;
    let inodes = |d: &Path| -> Vec<(u64, u64)> {
        std::fs::read_dir(d.join("objects/pack"))
            .map(|rd| {
                rd.flatten()
                    .filter_map(|e| std::fs::metadata(e.path()).ok())
                    .filter(|m| m.is_file() && m.nlink() > 1)
                    .map(|m| (m.dev(), m.ino()))
                    .collect()
            })
            .unwrap_or_default()
    };
    let theirs = inodes(parent);
    assert!(
        inodes(fork).iter().any(|i| theirs.contains(i)),
        "precondition: the fork must hardlink the parent's pack (C15)"
    );
}

/// Run git with `input` on stdin and the fixed identity.
fn git_stdin(cwd: &Path, args: &[&str], input: &str) -> String {
    use std::io::Write;
    let mut child = Command::new("git")
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
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("git runs");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// A commit in the bare store `dir` on top of `parent`, adding `file`.
fn bare_commit(dir: &Path, parent: &str, file: &str, body: &str, subject: &str) -> String {
    let blob = git_stdin(dir, &["hash-object", "-w", "--stdin"], body);
    let base = git(dir, &["ls-tree", &format!("{parent}^{{tree}}")]);
    let listing = format!("{base}\n100644 blob {blob}\t{file}\n");
    let tree = git_stdin(dir, &["mktree"], &listing);
    git(dir, &["commit-tree", &tree, "-p", parent, "-m", subject])
}

fn config_get(dir: &Path, key: &str) -> Option<String> {
    let out = Command::new("git")
        .args(["config", "--local", "--get", key])
        .current_dir(dir)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap();
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// The migration reports `mirror-recovery/<owner>/sample.git.<ts>.migration.json`.
fn reports_of(plugin: &Path, owner: &str) -> Vec<serde_json::Value> {
    recovery_entries(plugin, owner)
        .iter()
        .filter_map(|e| std::fs::read(sibling(e, ".migration.json")).ok())
        .map(|b| serde_json::from_slice(&b).unwrap())
        .collect()
}

fn migration_id_of(store: &Path) -> Option<String> {
    std::fs::read_to_string(store.join(MIGRATION_ID))
        .ok()
        .map(|s| s.trim().to_string())
}

/// Design test 6: a fork of a legacy mirror, made with the production fork
/// builder and then marked by hand (decision 19: the marker never decides
/// the sweep), is rebuilt. Held is denied on the fork's readers; the fork's
/// branches, its pull-request heads and `forge.parent` survive;
/// `receive.denyDeletes` is not set; the marker it had is kept.
#[tokio::test]
async fn b2_t6_a_fork_of_a_legacy_mirror_is_rebuilt() {
    let fx = legacy(190, Shape::Engine);
    let fork = make_fork(&fx.plugin, &fx.owner, "carol").await;
    assert_hardlinked(&fx.served, &fork);
    let feature = bare_commit(&fork, &fx.m2, "carol.txt", "b2-carol\n", "b2 carol");
    git(&fork, &["update-ref", "refs/heads/feature", &feature]);
    let pr = bare_commit(&fork, &fx.m2, "dave.txt", "b2-dave-pr\n", "b2 dave pr");
    git(&fork, &["update-ref", "refs/forge/heads/dave/x", &pr]);
    std::fs::write(fork.join(MARKER), format!("{MARKER}\n")).unwrap();
    assert!(
        has(&fork, &fx.held),
        "precondition: the fork holds the held commit"
    );
    let forge = forge_at(&fx.plugin);
    let leaks = held_leaks(&forge, "carol", &fx.held).await;
    assert!(
        leaks.is_empty(),
        "held commit served by the fork:\n{}",
        leaks.join("\n")
    );
    let ok = get(
        &forge,
        format!("/forge/carol/sample/raw/{feature}/carol.txt"),
    )
    .await;
    assert_eq!(ok.status, 200, "the fork's own branch is not served");
    let refs = refs_of(&fork);
    for r in [
        "refs/heads/main",
        "refs/heads/feature",
        "refs/forge/heads/dave/x",
    ] {
        assert!(refs.contains(r), "{r} lost from the fork:\n{refs}");
    }
    assert_eq!(
        config_get(&fork, "forge.parent").as_deref(),
        Some(format!("{}/sample", fx.owner).as_str()),
        "forge.parent lost"
    );
    assert_eq!(
        config_get(&fork, "receive.denyDeletes"),
        None,
        "a fork must not get the mirror's receive.denyDeletes"
    );
    assert!(
        fork.join(MARKER).is_file(),
        "the fork's marker was not kept"
    );
    for key in ["uploadpack.hideRefs", "transfer.hideRefs"] {
        assert_eq!(
            config_get(&fork, key).as_deref(),
            Some("refs/forge/"),
            "{key} lost from the fork"
        );
    }
    assert!(
        !journal_of(&fx.plugin, "carol").exists(),
        "fork journal left"
    );
    assert_eq!(
        recovery_entries(&fx.plugin, "carol").len(),
        1,
        "no fork recovery entry"
    );
    assert!(
        !has(&fork, &fx.held),
        "the held commit is still in the fork"
    );
}

/// Design test 7: a fork of a fork (transitive) is rebuilt (C2).
#[tokio::test]
async fn b2_t7_a_fork_of_a_fork_is_rebuilt() {
    let fx = legacy(191, Shape::Engine);
    let first = make_fork(&fx.plugin, &fx.owner, "carol").await;
    let second = make_fork(&fx.plugin, "carol", "dave").await;
    assert_hardlinked(&first, &second);
    assert!(
        has(&second, &fx.held),
        "precondition: the fork of a fork holds held"
    );
    let forge = forge_at(&fx.plugin);
    let leaks = held_leaks(&forge, "dave", &fx.held).await;
    assert!(
        leaks.is_empty(),
        "held commit served by the fork of a fork:\n{}",
        leaks.join("\n")
    );
    assert!(
        !has(&second, &fx.held),
        "the held commit is still in the fork of a fork"
    );
    assert_eq!(
        config_get(&second, "forge.parent").as_deref(),
        Some("carol/sample")
    );
}

/// The C17 shape: a legacy store whose held branch `side` was at `X1` when
/// carol forked it; upstream then force-pushed `side` to an unrelated `X2`
/// and the legacy store refetched. `(fixture, fork, X1, X2)`.
async fn c17_fixture(seed: u8) -> (Legacy, PathBuf, String, String) {
    let fx = legacy(seed, Shape::Engine);
    // Start from a store with nothing outside the roots but `refs/mirror`.
    for r in [
        "refs/misc/stash-held",
        "refs/misc/blob",
        "refs/notes/commits",
    ] {
        git(&fx.served, &["update-ref", "-d", r]);
    }
    git(
        &fx.served,
        &["update-ref", "-d", "refs/forge/heads/bob/feat"],
    );
    let x1 = fx.held.clone();
    let fork = make_fork(&fx.plugin, &fx.owner, "carol").await;
    assert_hardlinked(&fx.served, &fork);
    let up = fx.home.join("up");
    git(&up, &["checkout", "--quiet", "--orphan", "b2-x2"]);
    git(&up, &["rm", "-rf", "--quiet", "."]);
    std::fs::write(up.join("x2.txt"), "b2-unrelated-x2\n").unwrap();
    git(&up, &["add", "-A"]);
    git(&up, &["commit", "--quiet", "-m", "b2 x2"]);
    let x2 = git(&up, &["rev-parse", "HEAD"]);
    git(&up, &["branch", "-M", "b2-x2", "side"]);
    git(
        &fx.served,
        &[
            "fetch",
            "--quiet",
            "--no-tags",
            "--prune",
            up.to_str().unwrap(),
            "+refs/heads/*:refs/mirror/*",
        ],
    );
    assert_eq!(git(&fx.served, &["rev-parse", "refs/mirror/side"]), x2);
    assert!(has(&fork, &x1), "precondition: the fork still holds X1");
    assert!(
        !has(&fork, &x2),
        "precondition: X2 is not in the fork (H trigger misses)"
    );
    (fx, fork, x1, x2)
}

/// Design test 7b (C17): a fork taken before upstream force-pushed the held
/// branch away is rebuilt, and X1's held blob is denied on its readers. An
/// `H` trigger (current `refs/mirror` tips) has no hit in this fork.
#[tokio::test]
async fn b2_t7b_a_fork_taken_before_a_force_push_is_rebuilt() {
    let (fx, fork, x1, _x2) = c17_fixture(192).await;
    let forge = forge_at(&fx.plugin);
    let leaks = held_leaks(&forge, "carol", &x1).await;
    assert!(
        leaks.is_empty(),
        "X1 served by the fork:\n{}",
        leaks.join("\n")
    );
    assert!(!has(&fork, &x1), "X1 is still in the fork");
}

/// Design test 8 (C9, D1): a fork owner's ref reaching held is dropped and
/// listed in the fork's report; the fork's other refs survive.
#[tokio::test]
async fn b2_t8_a_fork_ref_reaching_held_is_dropped_and_reported() {
    let fx = legacy(193, Shape::Engine);
    let fork = make_fork(&fx.plugin, &fx.owner, "carol").await;
    assert_hardlinked(&fx.served, &fork);
    git(&fork, &["update-ref", "refs/heads/republished", &fx.held]);
    let feature = bare_commit(&fork, &fx.m2, "carol.txt", "b2-carol\n", "b2 carol");
    git(&fork, &["update-ref", "refs/heads/feature", &feature]);
    let forge = forge_at(&fx.plugin);
    let leaks = held_leaks(&forge, "carol", &fx.held).await;
    assert!(
        leaks.is_empty(),
        "held commit served by the fork:\n{}",
        leaks.join("\n")
    );
    let refs = refs_of(&fork);
    assert!(
        !refs.contains("refs/heads/republished"),
        "republished kept:\n{refs}"
    );
    assert!(refs.contains("refs/heads/feature"), "feature lost:\n{refs}");
    assert!(refs.contains("refs/heads/main"), "main lost:\n{refs}");
    let ok = get(
        &forge,
        format!("/forge/carol/sample/raw/{feature}/carol.txt"),
    )
    .await;
    assert_eq!(ok.status, 200, "the fork's own branch is not served");
    let reports = reports_of(&fx.plugin, "carol");
    assert_eq!(reports.len(), 1, "one fork report");
    let reason = dropped_reason(&reports[0], "refs/heads/republished");
    assert_eq!(
        reason.as_deref(),
        Some("reaches-held"),
        "republished is not reported: {}",
        reports[0]
    );
    assert_eq!(reports[0]["class"], "fork", "{}", reports[0]);
}

/// Design test 19 (D4): a `.fork-*.tmp` directory older than an hour is
/// moved out of `repos/` into recovery; a fresh one is left alone.
#[tokio::test]
async fn b2_t19_a_stale_partial_fork_is_moved_to_recovery() {
    let fx = legacy(194, Shape::Engine);
    let repos = fx.plugin.join("repos");
    let owner_dir = repos.join("carol");
    std::fs::create_dir_all(&owner_dir).unwrap();
    let stale = owner_dir.join(".fork-stale.tmp");
    crate::forks::build_fork_at(&repos, &fx.served, &stale, &fx.owner, "sample")
        .await
        .unwrap();
    assert_hardlinked(&fx.served, &stale);
    let fresh = owner_dir.join(".fork-fresh.tmp");
    crate::forks::build_fork_at(&repos, &fx.served, &fresh, &fx.owner, "sample")
        .await
        .unwrap();
    let old = std::time::SystemTime::now() - std::time::Duration::from_secs(2 * 3600);
    std::fs::File::open(&stale)
        .unwrap()
        .set_modified(old)
        .unwrap();
    drop(forge_at(&fx.plugin));
    assert!(
        !stale.exists(),
        "the stale partial fork is still under repos/"
    );
    assert!(fresh.exists(), "a fresh partial fork was moved");
    let moved: Vec<String> = std::fs::read_dir(fx.plugin.join("mirror-recovery/carol"))
        .map(|rd| {
            rd.flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    assert!(
        moved.iter().any(|n| n.starts_with(".fork-stale.tmp")),
        "the stale partial fork is not in recovery: {moved:?}"
    );
}

/// A fork whose config cannot be read: the pass is incomplete (decision 28)
/// and the fork is refused.
#[tokio::test]
async fn b2_an_unreadable_fork_config_makes_the_pass_incomplete_and_gates() {
    use std::os::unix::fs::PermissionsExt;
    let fx = legacy(195, Shape::Engine);
    let fork = make_fork(&fx.plugin, &fx.owner, "carol").await;
    assert_hardlinked(&fx.served, &fork);
    let config = fork.join("config");
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o000)).unwrap();
    let probe = std::fs::read(&config);
    let forge = forge_at(&fx.plugin);
    let leaks = held_leaks(&forge, "carol", &fx.held).await;
    let approved = get(
        &forge,
        format!("/forge/carol/sample/raw/{}/public.txt", fx.m2),
    )
    .await;
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(
        probe.is_err_and(|e| e.kind() == std::io::ErrorKind::PermissionDenied),
        "precondition: the fork's config must be unreadable (EACCES)"
    );
    assert!(
        forge.migration_incomplete,
        "the pass did not report incomplete"
    );
    assert!(
        leaks.is_empty(),
        "held commit served by the fork:\n{}",
        leaks.join("\n")
    );
    assert_eq!(approved.status, 503, "the fork is not gated");
}

/// A `forge.parent` loop (legacy M names its fork carol/sample as parent,
/// and carol/sample names M): the boot terminates, and the fork is swept.
#[test]
fn b2_a_fork_cycle_terminates_and_the_fork_is_swept() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (fx, fork) = rt.block_on(async {
        let fx = legacy(196, Shape::Engine);
        let fork = make_fork(&fx.plugin, &fx.owner, "carol").await;
        assert_hardlinked(&fx.served, &fork);
        git(&fx.served, &["config", "forge.parent", "carol/sample"]);
        (fx, fork)
    });
    let plugin = fx.plugin.clone();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(forge_at(&plugin));
    });
    let forge = rx
        .recv_timeout(std::time::Duration::from_secs(120))
        .expect("the boot did not terminate on a forge.parent cycle");
    rt.block_on(async {
        let leaks = held_leaks(&forge, "carol", &fx.held).await;
        assert!(
            leaks.is_empty(),
            "held commit served by the fork in a cycle:\n{}",
            leaks.join("\n")
        );
        let leaks = held_leaks(&forge, &fx.owner, &fx.held).await;
        assert!(
            leaks.is_empty(),
            "held served by the mirror:\n{}",
            leaks.join("\n")
        );
    });
    assert!(
        !has(&fork, &fx.held),
        "the held commit is still in the fork"
    );
}

/// A fork none of whose objects is in an ancestor's dropped set is left
/// untouched: no journal, no recovery entry, the same config bytes and the
/// same pack files.
#[tokio::test]
async fn b2_a_fork_with_no_dropped_object_is_left_untouched() {
    use std::os::unix::fs::MetadataExt;
    let fx = legacy(197, Shape::Engine);
    let fork = fx.plugin.join("repos/carol/sample.git");
    std::fs::create_dir_all(fork.parent().unwrap()).unwrap();
    git(
        &fx.home,
        &[
            "init",
            "--bare",
            "--quiet",
            "-b",
            "main",
            fork.to_str().unwrap(),
        ],
    );
    git(
        &fx.home.join("up"),
        &["push", "--quiet", fork.to_str().unwrap(), "main:main"],
    );
    git(
        &fork,
        &["config", "forge.parent", &format!("{}/sample", fx.owner)],
    );
    git(&fork, &["repack", "-a", "-d", "-q"]);
    keep_packs(&fork);
    let config = std::fs::read(fork.join("config")).unwrap();
    let packs = |d: &Path| -> Vec<(String, u64)> {
        let mut v: Vec<(String, u64)> = std::fs::read_dir(d.join("objects/pack"))
            .unwrap()
            .flatten()
            .map(|e| {
                (
                    e.file_name().to_string_lossy().into_owned(),
                    std::fs::metadata(e.path()).unwrap().ino(),
                )
            })
            .collect();
        v.sort();
        v
    };
    let before = packs(&fork);
    let forge = forge_at(&fx.plugin);
    assert!(
        !journal_of(&fx.plugin, "carol").exists(),
        "a journal was written"
    );
    assert!(
        !fx.plugin.join("mirror-recovery/carol").exists(),
        "the clean fork was moved to recovery"
    );
    assert_eq!(
        std::fs::read(fork.join("config")).unwrap(),
        config,
        "config changed"
    );
    assert_eq!(packs(&fork), before, "the fork's packs changed");
    assert!(
        migration_id_of(&fork).is_none(),
        "the clean fork was rebuilt"
    );
    let ok = get(
        &forge,
        format!("/forge/carol/sample/raw/{}/public.txt", fx.m2),
    )
    .await;
    assert_eq!(ok.status, 200, "the clean fork is not served");
}

/// A fork whose legacy parent cannot be migrated (t21's fsck-bad history)
/// has no dropped set to be checked against: it is gated.
#[tokio::test]
async fn b2_a_fork_of_an_unmigrated_parent_is_gated() {
    let fx = legacy(198, Shape::Engine);
    let tree = git(&fx.served, &["rev-parse", &format!("{}^{{tree}}", fx.m2)]);
    let raw = format!(
        "tree {tree}\nparent {}\nauthor t <t@t> 1700000000 +99999\ncommitter t <t@t> 1700000000 +0000\n\nb2 bad zone\n",
        fx.m2
    );
    let bad = git_stdin(
        &fx.served,
        &[
            "hash-object",
            "--literally",
            "-t",
            "commit",
            "-w",
            "--stdin",
        ],
        &raw,
    );
    git(&fx.served, &["update-ref", "refs/heads/main", &bad]);
    let fork = make_fork(&fx.plugin, &fx.owner, "carol").await;
    assert_hardlinked(&fx.served, &fork);
    let forge = forge_at(&fx.plugin);
    assert!(
        journal_of(&fx.plugin, &fx.owner).exists(),
        "precondition: the parent's migration failed"
    );
    let leaks = held_leaks(&forge, "carol", &fx.held).await;
    assert!(
        leaks.is_empty(),
        "held commit served by the fork of an unmigrated parent:\n{}",
        leaks.join("\n")
    );
    let approved = get(
        &forge,
        format!("/forge/carol/sample/raw/{}/public.txt", fx.m2),
    )
    .await;
    assert_eq!(approved.status, 503, "the fork is not gated");
}

/// A followed fork (a fork with a mirror record) gets both treatments: the
/// mirror's config and marker, and its refs, roots included, filtered
/// against the inherited held set; `forge.parent` is kept.
#[tokio::test]
async fn b2_a_followed_fork_gets_both_treatments() {
    let fx = legacy(199, Shape::Engine);
    let follower = owner_of(189);
    let fork = make_fork(&fx.plugin, &fx.owner, &follower).await;
    assert_hardlinked(&fx.served, &fork);
    git(&fork, &["update-ref", "refs/heads/side", &fx.held]);
    write_record(
        &fx.plugin,
        &follower,
        pre_release_record(&follower).as_bytes(),
    );
    let forge = forge_at(&fx.plugin);
    let leaks = held_leaks(&forge, &follower, &fx.held).await;
    assert!(
        leaks.is_empty(),
        "held commit served by the followed fork:\n{}",
        leaks.join("\n")
    );
    let refs = refs_of(&fork);
    assert!(
        !refs.contains("refs/heads/side"),
        "the held branch was kept:\n{refs}"
    );
    assert!(refs.contains("refs/heads/main"), "main lost:\n{refs}");
    assert!(
        fork.join(MARKER).is_file(),
        "the followed fork is not marked"
    );
    assert_eq!(
        config_get(&fork, "receive.denyDeletes").as_deref(),
        Some("true"),
        "the followed fork lacks the mirror config"
    );
    assert_eq!(
        config_get(&fork, "forge.parent").as_deref(),
        Some(format!("{}/sample", fx.owner).as_str()),
        "forge.parent lost"
    );
    let ok = get(
        &forge,
        format!("/forge/{follower}/sample/raw/{}/public.txt", fx.m2),
    )
    .await;
    assert_eq!(ok.status, 200, "the followed fork is not served");
}

/// A rebuilt fork that keeps a ref at X1 (risk 4: X1 is in the parent's
/// dropped set but not in its held set) is not rebuilt again on the next
/// boot, and the parent's report is stamped `forksCleanAt`.
#[tokio::test]
async fn b2_a_rebuilt_fork_is_not_rebuilt_again_and_the_parent_is_stamped() {
    let (fx, fork, x1, _x2) = c17_fixture(188).await;
    git(&fork, &["update-ref", "refs/heads/keep-x1", &x1]);
    drop(forge_at(&fx.plugin));
    let id = migration_id_of(&fork).expect("boot 1 did not rebuild the fork");
    let entries = recovery_entries(&fx.plugin, "carol");
    assert_eq!(entries.len(), 1, "boot 1: one fork recovery entry");
    assert!(has(&fork, &x1), "risk 4: the fork ref at X1 is kept");
    drop(forge_at(&fx.plugin));
    assert_eq!(
        migration_id_of(&fork).as_deref(),
        Some(id.as_str()),
        "boot 2 rebuilt the fork"
    );
    assert_eq!(
        recovery_entries(&fx.plugin, "carol"),
        entries,
        "boot 2 made a recovery entry"
    );
    let parent = reports_of(&fx.plugin, &fx.owner);
    assert_eq!(parent.len(), 1);
    assert!(
        parent[0]
            .get("forksCleanAt")
            .is_some_and(|v| v.as_u64().is_some()),
        "the parent's report is not stamped: {}",
        parent[0]
    );
}

/// Item 6: a fork of a source with a migration journal is refused (503)
/// through `resolve_repo`; a fork onto a journalled target is covered by
/// `f12_a_fork_onto_a_journalled_name_is_refused`.
#[tokio::test]
async fn b2_a_fork_of_a_journalled_source_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path();
    let plugin = home.join("plugin");
    bare_with_commit(home, &plugin.join("repos/alice/src.git"), "b2-src\n");
    let forge = forge_at(&plugin);
    let journal = plugin.join("mirror-work/migrations/alice/src.json");
    std::fs::create_dir_all(journal.parent().unwrap()).unwrap();
    std::fs::write(
        &journal,
        r#"{"id":"s","ts":1,"class":"fork","state":"building","recovery":"mirror-recovery/alice/src.git.1","attempts":0}"#,
    )
    .unwrap();
    let caller = owner_of(187);
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
    assert_eq!(status, 503, "a fork of a journalled source was made");
    assert!(!plugin
        .join("repos")
        .join(&caller)
        .join("sample.git")
        .exists());
}

/// Plant a fork journal for `<owner>/sample` naming `parent`.
fn plant_fork_journal(plugin: &Path, owner: &str, parent: &str, reason: &str, attempts: u32) {
    let journal = plugin
        .join("mirror-work/migrations")
        .join(owner)
        .join("sample.json");
    std::fs::create_dir_all(journal.parent().unwrap()).unwrap();
    std::fs::write(
        &journal,
        format!(
            r#"{{"id":"planted","ts":1,"class":"fork","state":"failed","recovery":"mirror-recovery/{owner}/sample.git.1","attempts":{attempts},"reason":"{reason}","parent":"{parent}"}}"#
        ),
    )
    .unwrap();
}

/// A fork with an existing (not detection-error) journal whose ancestor is
/// gated is not rebuilt: with no ancestor reports there is no held set to
/// filter against, so a rebuild would publish a ref reaching held.
#[tokio::test]
async fn b2_a_journalled_fork_with_a_gated_ancestor_is_not_rebuilt() {
    let fx = legacy(186, Shape::Engine);
    let fork = make_fork(&fx.plugin, &fx.owner, "carol").await;
    assert_hardlinked(&fx.served, &fork);
    git(&fork, &["update-ref", "refs/heads/republished", &fx.held]);
    let tree = git(&fx.served, &["rev-parse", &format!("{}^{{tree}}", fx.m2)]);
    let raw = format!(
        "tree {tree}\nparent {}\nauthor t <t@t> 1700000000 +99999\ncommitter t <t@t> 1700000000 +0000\n\nb2 bad zone\n",
        fx.m2
    );
    let bad = git_stdin(
        &fx.served,
        &[
            "hash-object",
            "--literally",
            "-t",
            "commit",
            "-w",
            "--stdin",
        ],
        &raw,
    );
    git(&fx.served, &["update-ref", "refs/heads/main", &bad]);
    plant_fork_journal(
        &fx.plugin,
        "carol",
        &format!("{}/sample", fx.owner),
        "push into staging failed",
        1,
    );
    let forge = forge_at(&fx.plugin);
    assert!(
        journal_of(&fx.plugin, &fx.owner).exists(),
        "precondition: the parent's migration failed"
    );
    let leaks = held_leaks(&forge, "carol", &fx.held).await;
    assert!(
        leaks.is_empty(),
        "held commit served by the fork:\n{}",
        leaks.join("\n")
    );
    assert!(
        journal_of(&fx.plugin, "carol").exists(),
        "the fork journal was removed"
    );
    assert!(
        recovery_entries(&fx.plugin, "carol").is_empty(),
        "the fork was rebuilt without its ancestors' held set"
    );
    let approved = get(
        &forge,
        format!("/forge/carol/sample/raw/{}/public.txt", fx.m2),
    )
    .await;
    assert_eq!(approved.status, 503, "the fork is not gated");
}

/// A rebuilt fork keeping a ref at X1 (risk 4) is not rebuilt again even
/// when stamping stays blocked (another fork of the parent, erin's, has
/// given up): the fork report's `ancestors` covers the parent's report.
#[tokio::test]
async fn b2_a_rebuilt_fork_is_not_rebuilt_again_while_stamping_is_blocked() {
    let (fx, fork, x1, _x2) = c17_fixture(185).await;
    git(&fork, &["update-ref", "refs/heads/keep-x1", &x1]);
    plant_fork_journal(
        &fx.plugin,
        "erin",
        &format!("{}/sample", fx.owner),
        "push into staging failed",
        3,
    );
    drop(forge_at(&fx.plugin));
    let id = migration_id_of(&fork).expect("boot 1 did not rebuild the fork");
    let entries = recovery_entries(&fx.plugin, "carol");
    assert_eq!(entries.len(), 1, "boot 1: one fork recovery entry");
    drop(forge_at(&fx.plugin));
    let parent = reports_of(&fx.plugin, &fx.owner);
    assert_eq!(parent.len(), 1);
    assert!(
        parent[0].get("forksCleanAt").is_none(),
        "precondition: stamping must stay blocked: {}",
        parent[0]
    );
    assert_eq!(
        migration_id_of(&fork).as_deref(),
        Some(id.as_str()),
        "boot 2 rebuilt the fork"
    );
    assert_eq!(
        recovery_entries(&fx.plugin, "carol"),
        entries,
        "boot 2 made a recovery entry"
    );
}

// ---- B2 fix round 1 -----------------------------------------------------

/// Held denial on the raw, HTML and archive readers of `<o>/<seg>`, where
/// `seg` is the URL segment (`foo.git.git` for a store named `foo.git`;
/// the JSON API refuses such a name on its own).
async fn held_leaks_at(forge: &crate::ForgeService, o: &str, seg: &str, h: &str) -> Vec<String> {
    let paths = [
        format!("/forge/{o}/{seg}/raw/{h}/held.txt"),
        format!("/forge/{o}/{seg}/blob/{h}/held.txt"),
        format!("/forge/{o}/{seg}/tree/{h}"),
        format!("/forge/{o}/{seg}/commit/{h}"),
        format!("/forge/{o}/{seg}/archive/{h}.tar.gz"),
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

/// Item 1 (F1): a legacy mirror named `foo.git` (served as
/// `repos/<hex>/foo.git.git`), forked to `carol/foo.git` by the production
/// fork builder, records `forge.parent = <hex>/foo.git`, which the strict
/// lineage parser rejects (`valid_repo` refuses a `.git` suffix). The sweep
/// must still see and rebuild the fork: held is denied on carol's raw, HTML
/// and archive readers.
#[tokio::test]
async fn b2f1_a_fork_of_a_dot_git_named_mirror_is_swept() {
    let fx = legacy(176, Shape::Engine);
    let repos = fx.plugin.join("repos");
    let src = repos.join(&fx.owner).join("foo.git.git");
    std::fs::rename(&fx.served, &src).unwrap();
    let owner_dir = repos.join("carol");
    std::fs::create_dir_all(&owner_dir).unwrap();
    let tmp = owner_dir.join(format!(".fork-{}.tmp", uuid::Uuid::new_v4()));
    crate::forks::build_fork_at(&repos, &src, &tmp, &fx.owner, "foo.git")
        .await
        .expect("the fork builds");
    let fork = owner_dir.join("foo.git.git");
    std::fs::rename(&tmp, &fork).unwrap();
    assert_hardlinked(&src, &fork);
    assert_eq!(
        config_get(&fork, "forge.parent"),
        Some(format!("{}/foo.git", fx.owner)),
        "precondition: the production builder records the lineage"
    );
    let conf = std::fs::read_to_string(fork.join("config")).unwrap();
    assert!(
        crate::forks::parse_fork_parent(&conf).is_none(),
        "precondition: the strict parser rejects this lineage"
    );
    assert!(
        has(&fork, &fx.held),
        "precondition: the fork holds the held commit"
    );
    let forge = forge_at(&fx.plugin);
    let leaks = held_leaks_at(&forge, "carol", "foo.git.git", &fx.held).await;
    assert!(
        leaks.is_empty(),
        "held commit served by the fork of a mirror named foo.git:\n{}",
        leaks.join("\n")
    );
    let ok = get(
        &forge,
        format!("/forge/carol/foo.git.git/raw/{}/public.txt", fx.m2),
    )
    .await;
    assert_eq!(
        ok.status, 200,
        "the swept fork's approved content is not served"
    );
    assert!(
        !has(&fork, &fx.held),
        "the held commit is still in the fork"
    );
}

/// Item 1: a `forge.parent` that is present but unparseable (`x/y/z`) is a
/// fork of unknown lineage. It gets the orphan treatment (checked against
/// every mirror-class report, so this hardlinked fork is rebuilt), keeps its
/// lineage, and never lets a report be stamped.
#[tokio::test]
async fn b2f1_a_fork_of_unknown_lineage_is_checked_against_every_report() {
    let fx = legacy(177, Shape::Engine);
    let fork = make_fork(&fx.plugin, &fx.owner, "carol").await;
    assert_hardlinked(&fx.served, &fork);
    git(&fork, &["config", "--local", "forge.parent", "x/y/z"]);
    assert!(
        has(&fork, &fx.held),
        "precondition: the fork holds the held commit"
    );
    let forge = forge_at(&fx.plugin);
    let leaks = held_leaks(&forge, "carol", &fx.held).await;
    assert!(
        leaks.is_empty(),
        "held commit served by a fork of unknown lineage:\n{}",
        leaks.join("\n")
    );
    let ok = get(
        &forge,
        format!("/forge/carol/sample/raw/{}/public.txt", fx.m2),
    )
    .await;
    assert_eq!(
        ok.status, 200,
        "the swept fork's approved content is not served"
    );
    assert_eq!(
        config_get(&fork, "forge.parent").as_deref(),
        Some("x/y/z"),
        "the unknown lineage was not kept"
    );
    let parent = reports_of(&fx.plugin, &fx.owner);
    assert_eq!(parent.len(), 1, "precondition: the parent migrated");
    assert!(
        parent[0].get("forksCleanAt").is_none(),
        "a fork of unknown lineage let the parent's report be stamped: {}",
        parent[0]
    );
}

/// Item 1: while the pass is incomplete (erin's config is unreadable), a
/// store whose `forge.parent` is present but unparseable is refused like
/// any other fork.
#[tokio::test]
async fn b2f1_a_fork_of_unknown_lineage_is_gated_while_the_pass_is_incomplete() {
    use std::os::unix::fs::PermissionsExt;
    let fx = legacy(178, Shape::Engine);
    let fork = make_fork(&fx.plugin, &fx.owner, "carol").await;
    assert_hardlinked(&fx.served, &fork);
    git(&fork, &["config", "--local", "forge.parent", "x/y/z"]);
    let other = make_fork(&fx.plugin, &fx.owner, "erin").await;
    let config = other.join("config");
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o000)).unwrap();
    let probe = std::fs::read(&config);
    let forge = forge_at(&fx.plugin);
    let approved = get(
        &forge,
        format!("/forge/carol/sample/raw/{}/public.txt", fx.m2),
    )
    .await;
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(
        probe.is_err_and(|e| e.kind() == std::io::ErrorKind::PermissionDenied),
        "precondition: erin's config must be unreadable (EACCES)"
    );
    assert!(
        forge.migration_incomplete,
        "precondition: the pass must be incomplete"
    );
    assert_eq!(
        approved.status, 503,
        "a fork of unknown lineage is served while the pass is incomplete"
    );
}

/// Item 1: `h_api_fork` refuses to write a lineage the parser would reject
/// (a source named `foo.git`), so no new fork of unknown lineage is made.
#[tokio::test]
async fn b2f1_a_fork_whose_lineage_the_parser_rejects_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path();
    let plugin = home.join("plugin");
    bare_with_commit(home, &plugin.join("repos/alice/foo.git.git"), "b2-src\n");
    let caller = owner_of(179);
    let forge = forge_at(&plugin);
    let r = req("POST", "/forge/api/repos/alice/foo.git.git/fork", "");
    let got = forge
        .handle(
            r,
            crate::ForgeAgent::Nostr {
                pubkey_hex: caller.clone(),
            },
        )
        .await;
    let status = got.map_or_else(|e| e.status_code(), |r| r.status);
    assert_eq!(status, 422, "a fork with an unparseable lineage was made");
    assert!(!plugin
        .join("repos")
        .join(&caller)
        .join("foo.git.git")
        .exists());
}

/// Item 2 (F2): carol forked the legacy store while it held X1; upstream
/// then force-pushed X1 away and the legacy engine's `gc` pruned it from the
/// parent, so X1 is in neither the parent's held nor its dropped set. The
/// fork still holds X1 in its hardlinked pack, unreachable from its refs:
/// it is rebuilt, and X1 is denied.
#[tokio::test]
async fn b2f1_a_fork_keeping_an_object_pruned_from_the_parent_is_rebuilt() {
    let (fx, fork, x1, _x2) = c17_fixture(182).await;
    prune_from_parent(&fx, &fork, &x1);
    let forge = forge_at(&fx.plugin);
    assert_not_dropped(&fx, &x1);
    let leaks = held_leaks(&forge, "carol", &x1).await;
    assert!(
        leaks.is_empty(),
        "X1, pruned from the parent, served by the fork:\n{}",
        leaks.join("\n")
    );
    assert!(!has(&fork, &x1), "X1 is still in the fork");
    assert_eq!(
        recovery_entries(&fx.plugin, "carol").len(),
        1,
        "the fork was not rebuilt"
    );
}

/// The legacy engine's `gc`: X1, force-pushed away upstream, is pruned from
/// the parent (its `.keep` removed first), while carol's hardlinked pack,
/// `.keep` included, still holds it.
fn prune_from_parent(fx: &Legacy, fork: &Path, x1: &str) {
    for e in std::fs::read_dir(fx.served.join("objects/pack"))
        .unwrap()
        .flatten()
    {
        if e.path().extension().is_some_and(|x| x == "keep") {
            std::fs::remove_file(e.path()).unwrap();
        }
    }
    git(&fx.served, &["reflog", "expire", "--expire=now", "--all"]);
    git(&fx.served, &["gc", "--quiet", "--prune=now"]);
    assert!(
        !has(&fx.served, x1),
        "precondition: X1 pruned from the parent"
    );
    assert!(has(fork, x1), "precondition: the fork still holds X1");
    let keeps = std::fs::read_dir(fork.join("objects/pack"))
        .unwrap()
        .flatten()
        .filter(|e| e.path().extension().is_some_and(|x| x == "keep"))
        .count();
    assert!(keeps > 0, "precondition: the fork keeps its .keep pack");
}

/// Precondition, after boot: X1 is not in the parent's dropped set.
fn assert_not_dropped(fx: &Legacy, x1: &str) {
    let entries = recovery_entries(&fx.plugin, &fx.owner);
    assert_eq!(entries.len(), 1, "precondition: the parent migrated");
    let dropped = std::fs::read_to_string(sibling(&entries[0], ".dropped")).unwrap();
    assert!(
        !dropped.lines().any(|l| l == x1),
        "precondition: X1 is not in the parent's dropped set"
    );
}

/// Item 2 (advisor review): reachability is counted only through refs the
/// rebuild keeps. A fork ref under `refs/mirror/` or `refs/replace/` that
/// reaches the pruned X1 is dropped by the rebuild, so it must not make X1
/// count as reachable.
#[tokio::test]
async fn b2f1_a_pruned_object_reached_only_by_dropped_refs_is_removed() {
    let (fx, fork, x1, _x2) = c17_fixture(200).await;
    prune_from_parent(&fx, &fork, &x1);
    git(&fork, &["update-ref", "refs/mirror/old-side", &x1]);
    git(
        &fork,
        &[
            "update-ref",
            "refs/replace/0000000000000000000000000000000000000001",
            &x1,
        ],
    );
    // Every other object the hardlinked pack carries unreachable (the
    // legacy notes, stash and pull-request objects) is reached the same way,
    // so only the excluded refs reach anything outside the kept refs.
    let dangling = git(
        &fork,
        &["fsck", "--dangling", "--no-reflogs", "--no-progress"],
    );
    for (i, line) in dangling.lines().enumerate() {
        let sha = line.rsplit(' ').next().unwrap();
        git(
            &fork,
            &["update-ref", &format!("refs/mirror/dangling-{i}"), sha],
        );
    }
    let count = |args: &[&str]| git(&fork, args).lines().count();
    assert_eq!(
        count(&[
            "cat-file",
            "--batch-all-objects",
            "--batch-check=%(objectname)"
        ]),
        count(&["rev-list", "--objects", "--all"]),
        "precondition: every object in the fork is reachable from some ref"
    );
    let forge = forge_at(&fx.plugin);
    assert_not_dropped(&fx, &x1);
    let leaks = held_leaks(&forge, "carol", &x1).await;
    assert!(
        leaks.is_empty(),
        "X1, reached only by refs the rebuild drops, served by the fork:\n{}",
        leaks.join("\n")
    );
    assert!(!has(&fork, &x1), "X1 is still in the fork");
    assert_eq!(
        recovery_entries(&fx.plugin, "carol").len(),
        1,
        "the fork was not rebuilt"
    );
}

/// Item 4 (Codex Medium 2): a journalled ancestor fork under a non-hex
/// owner (carol, given up after three attempts) gates its descendant dave.
#[tokio::test]
async fn b2f1_a_journalled_ancestor_fork_under_any_owner_gates_its_descendants() {
    let fx = legacy(183, Shape::Engine);
    let carol = make_fork(&fx.plugin, &fx.owner, "carol").await;
    let dave = make_fork(&fx.plugin, "carol", "dave").await;
    assert_hardlinked(&carol, &dave);
    plant_fork_journal(
        &fx.plugin,
        "carol",
        &format!("{}/sample", fx.owner),
        "push into staging failed",
        3,
    );
    let forge = forge_at(&fx.plugin);
    assert!(
        journal_of(&fx.plugin, "carol").exists(),
        "precondition: carol's journal stays"
    );
    let leaks = held_leaks(&forge, "dave", &fx.held).await;
    assert!(
        leaks.is_empty(),
        "held commit served by dave:\n{}",
        leaks.join("\n")
    );
    let approved = get(
        &forge,
        format!("/forge/dave/sample/raw/{}/public.txt", fx.m2),
    )
    .await;
    assert_eq!(
        approved.status, 503,
        "a descendant of a journalled fork is served"
    );
    assert!(
        journal_of(&fx.plugin, "dave").exists(),
        "the descendant is not gated by a journal"
    );
}

/// Item 5 (Codex fail-open 3): a fork crash-resumed after the second rename
/// (`published`, the served store carrying the journal's id) whose ancestor
/// is now gated is not published: its journal stays.
#[tokio::test]
async fn b2f1_a_crash_resumed_fork_with_a_gated_ancestor_keeps_its_journal() {
    let fx = legacy(184, Shape::Engine);
    let fork = make_fork(&fx.plugin, &fx.owner, "carol").await;
    assert_hardlinked(&fx.served, &fork);
    drop(forge_at(&fx.plugin));
    let id = migration_id_of(&fork).expect("boot 1 did not rebuild the fork");
    let entries = recovery_entries(&fx.plugin, "carol");
    assert_eq!(entries.len(), 1, "boot 1: one fork recovery entry");
    let rel = entries[0]
        .strip_prefix(&fx.plugin)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    // Rewind carol to a crash after the second rename.
    plant_journal(
        &fx.plugin,
        "carol",
        &format!(
            r#"{{"id":"{id}","ts":1,"class":"fork","state":"published","moved":true,"recovery":"{rel}","attempts":0,"parent":"{}/sample"}}"#,
            fx.owner
        ),
    );
    // Gate the ancestor: a mirror journal that has given up.
    plant_journal(
        &fx.plugin,
        &fx.owner,
        &format!(
            r#"{{"id":"planted","ts":1,"class":"mirror","state":"failed","recovery":"mirror-recovery/{}/sample.git.1","attempts":3,"reason":"push into staging failed"}}"#,
            fx.owner
        ),
    );
    let forge = forge_at(&fx.plugin);
    assert!(
        journal_of(&fx.plugin, &fx.owner).exists(),
        "precondition: the ancestor stays gated"
    );
    assert!(
        journal_of(&fx.plugin, "carol").exists(),
        "a crash-resumed fork with a gated ancestor had its journal removed"
    );
    let approved = get(
        &forge,
        format!("/forge/carol/sample/raw/{}/public.txt", fx.m2),
    )
    .await;
    assert_eq!(approved.status, 503, "the fork is not gated");
}
