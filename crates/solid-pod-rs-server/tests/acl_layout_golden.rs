//! Golden decision matrix for the container-ACL location (SP-PAR-290),
//! committed against the code as it stood before the opt-in `--acl-layout`
//! setting existed. Every expected value is a literal taken from the default
//! behaviour (`sidecar`: a container's ACL is read at `<container>.acl`, an
//! inner `<container>/.acl` is ignored) and the test asserts that the default
//! keeps producing exactly this table.
//!
//! Rows: disk state. Columns: for each of the owner, a second agent B (Control
//! on the root through `acl:default`), and an anonymous caller, the status of
//! reads of the container, a child and a grandchild; writes (PUT) of a child, a
//! grandchild and a new file; and reads of the two ACL forms (`/docs.acl`,
//! which needs Control on `/docs`, and `/docs/.acl`, which needs Control on
//! `/docs/`).

mod common;
use common::acl_harness::*;
use solid_pod_rs_server::AppState;

#[actix_web::test]
async fn default_layout_decision_matrix_is_pinned() {
    let owner = agent(1);
    let b = agent(2);
    let mut table = Vec::new();
    for disk in ALL {
        let s = storage(disk, &owner, &b).await;
        let r = row(|| AppState::new(s.clone()), &owner, &b).await;
        table.push(format!("{disk:?} => {r}"));
    }
    println!("GOLDEN\n{}", table.join("\n"));
    let expected = include_str!("fixtures/acl_layout_golden.txt");
    assert_eq!(table.join("\n"), expected.trim_end());
}

/// `Link: rel="acl"` for a container and for a resource, default layout.
#[actix_web::test]
async fn default_layout_link_headers_are_pinned() {
    let owner = agent(1);
    let b = agent(2);
    let s = storage(Disk::None, &owner, &b).await;
    let (_, container) = call(AppState::new(s.clone()), Some(&owner), "HEAD", "/docs/", "").await;
    let (_, resource) = call(
        AppState::new(s.clone()),
        Some(&owner),
        "HEAD",
        "/docs/a.txt",
        "",
    )
    .await;
    let acl_of = |l: Option<String>| {
        l.unwrap()
            .split(", ")
            .find(|p| p.contains("rel=\"acl\""))
            .map(str::to_string)
            .unwrap()
    };
    assert_eq!(acl_of(container), "</docs.acl>; rel=\"acl\"");
    assert_eq!(acl_of(resource), "</docs/a.txt.acl>; rel=\"acl\"");
}
