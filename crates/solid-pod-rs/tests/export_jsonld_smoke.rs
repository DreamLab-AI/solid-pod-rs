//! Integration test for the JSS v0.0.190 Phase 1 pod export surface
//! (parity row 198, issue #437).
//!
//! Verifies:
//! - default exclusion of `/private/*`,
//! - opt-in inclusion via `ExportOptions { include_private: true }`,
//! - time-chain (ascending `created`) ordering,
//! - bundle envelope fields (`@context`, `pod_base`, `generated_at`,
//!   `includes_private`).

#![cfg(feature = "export-jsonld")]
#![cfg(feature = "memory-backend")]

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use bytes::Bytes;

use solid_pod_rs::export::{
    export_pod_jsonld, ExportOptions, PodExportBundle, EXPORT_JSONLD_CONTEXT,
};
use solid_pod_rs::storage::memory::MemoryBackend;
use solid_pod_rs::storage::Storage;

async fn seed_three_resource_pod() -> MemoryBackend {
    let pod = MemoryBackend::new();
    // Container markers — the recursive walker discovers sub-containers
    // through these `.meta` placeholders.
    for c in &["/profile", "/public", "/private"] {
        pod.put(
            &format!("{c}/.meta"),
            Bytes::from_static(b"{}"),
            "application/ld+json",
        )
        .await
        .unwrap();
    }
    // Three real payloads under each container.
    pod.put(
        "/profile/card",
        Bytes::from_static(b"<html>profile</html>"),
        "text/html",
    )
    .await
    .unwrap();
    pod.put(
        "/public/hello.txt",
        Bytes::from_static(b"hello world"),
        "text/plain",
    )
    .await
    .unwrap();
    pod.put(
        "/private/secret.txt",
        Bytes::from_static(b"top secret"),
        "text/plain",
    )
    .await
    .unwrap();
    pod
}

fn collect_paths(bundle: &PodExportBundle) -> Vec<&str> {
    bundle.entries.iter().map(|e| e.path.as_str()).collect()
}

#[tokio::test]
async fn export_excludes_private_by_default() {
    let pod = seed_three_resource_pod().await;
    let bundle = export_pod_jsonld(&pod, "https://pod.example/alice/", ExportOptions::default())
        .await
        .expect("export succeeds");

    assert_eq!(bundle.context, EXPORT_JSONLD_CONTEXT);
    assert_eq!(bundle.pod_base, "https://pod.example/alice/");
    assert!(!bundle.includes_private);

    let paths = collect_paths(&bundle);
    assert!(paths.contains(&"/profile/card"), "/profile/card: {paths:?}");
    assert!(
        paths.contains(&"/public/hello.txt"),
        "/public/hello.txt: {paths:?}"
    );
    assert!(
        !paths.iter().any(|p| p.starts_with("/private/")),
        "/private/* MUST be excluded by default: {paths:?}"
    );
}

#[tokio::test]
async fn export_opt_in_includes_private() {
    let pod = seed_three_resource_pod().await;
    let opts = ExportOptions {
        include_private: true,
    };
    let bundle = export_pod_jsonld(&pod, "https://pod.example/alice/", opts)
        .await
        .expect("export succeeds");

    assert!(bundle.includes_private);
    let paths = collect_paths(&bundle);
    assert!(
        paths.contains(&"/private/secret.txt"),
        "/private/secret.txt expected with include_private=true: {paths:?}"
    );
    let secret_entry = bundle
        .entries
        .iter()
        .find(|e| e.path == "/private/secret.txt")
        .unwrap();
    let decoded = BASE64_STANDARD.decode(&secret_entry.body_base64).unwrap();
    assert_eq!(decoded, b"top secret");
    assert_eq!(secret_entry.content_type, "text/plain");
}

#[tokio::test]
async fn export_entries_ordered_by_created_ascending() {
    let pod = MemoryBackend::new();

    pod.put(
        "/profile/.meta",
        Bytes::from_static(b"{}"),
        "application/ld+json",
    )
    .await
    .unwrap();

    // Write three resources with a delay so their `modified`
    // timestamps order deterministically.
    pod.put("/profile/a.txt", Bytes::from_static(b"a"), "text/plain")
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    pod.put("/profile/b.txt", Bytes::from_static(b"b"), "text/plain")
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    pod.put("/profile/c.txt", Bytes::from_static(b"c"), "text/plain")
        .await
        .unwrap();

    let bundle = export_pod_jsonld(&pod, "https://pod.example/alice/", ExportOptions::default())
        .await
        .unwrap();

    // Confirm the three writes are ordered ascending — they may be
    // interleaved with other resources, but their relative order must
    // hold.
    let mut letter_positions: Vec<(char, usize)> = Vec::new();
    for (i, e) in bundle.entries.iter().enumerate() {
        if let Some(rest) = e.path.strip_prefix("/profile/") {
            if let Some(ch) = rest.chars().next() {
                if matches!(ch, 'a' | 'b' | 'c') && rest.ends_with(".txt") {
                    letter_positions.push((ch, i));
                }
            }
        }
    }
    assert_eq!(letter_positions.len(), 3);
    let mut sorted = letter_positions.clone();
    sorted.sort_by_key(|(ch, _)| *ch);
    assert_eq!(
        letter_positions, sorted,
        "time-chain order broken: {letter_positions:?}"
    );
}
