//! `invite create | list | revoke` against the real binary (parity row 83,
//! JSS `bin/jss.js` 457-540): invites survive the process and are shared
//! by the three subcommands through `<root>/.server/invites.json`.

use std::process::Command;

fn run(root: &std::path::Path, args: &[&str]) -> std::process::Output {
    // `--root` is a global option of the `invite` command; env must not leak in.
    Command::new(env!("CARGO_BIN_EXE_solid-pod-rs-server"))
        .env_remove("JSS_STORAGE_ROOT")
        .arg("invite")
        .arg("--root")
        .arg(root)
        .args(args)
        .output()
        .expect("run binary")
}

fn field(out: &str, key: &str) -> String {
    out.lines()
        .find_map(|l| l.strip_prefix(key))
        .unwrap_or_else(|| panic!("no {key} in {out}"))
        .trim()
        .to_string()
}

#[test]
fn create_list_revoke_persist_between_processes() {
    let dir = tempfile::tempdir().unwrap();

    let empty = run(dir.path(), &["list"]);
    assert!(empty.status.success());
    assert!(String::from_utf8_lossy(&empty.stdout).contains("No invite codes found"));

    let created = run(dir.path(), &["create", "-u", "3"]);
    assert!(created.status.success(), "{created:?}");
    let token = field(&String::from_utf8_lossy(&created.stdout), "token:");

    let listed = run(dir.path(), &["list"]);
    let text = String::from_utf8_lossy(&listed.stdout).to_string();
    // Tokens are hashed at rest, so the list shows an id, never the token.
    assert!(!text.contains(&token), "{text}");
    assert!(text.contains("ID  USES"), "{text}");
    let raw = std::fs::read_to_string(dir.path().join(".server/invites.json")).unwrap();
    assert!(!raw.contains(&token), "token must not be stored in clear");
    assert!(text.contains("0/3"), "{text}");

    let revoked = run(dir.path(), &["revoke", &token]);
    assert!(revoked.status.success());
    assert!(String::from_utf8_lossy(&revoked.stdout).contains("Revoked invite code"));

    // Unknown (already revoked) token: non-zero exit, as JSS.
    let again = run(dir.path(), &["revoke", &token]);
    assert!(!again.status.success());

    let after = run(dir.path(), &["list"]);
    assert!(String::from_utf8_lossy(&after.stdout).contains("No invite codes found"));
}
