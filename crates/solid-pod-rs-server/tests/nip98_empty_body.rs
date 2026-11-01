//! Empty PUT bodies remain part of the signed request, including replay admission order.
use actix_web::{http::StatusCode, test};
use bytes::Bytes;
use solid_pod_rs::{
    auth::nip98,
    storage::{memory::MemoryBackend, Storage},
};
use solid_pod_rs_server::{build_app, AppState};
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

#[actix_web::test]
async fn put_binds_empty_content_before_consuming_the_token() {
    let secret = hex::encode([0x32; 32]);
    let signing = k256::schnorr::SigningKey::from_slice(&[0x32; 32]).unwrap();
    let did = format!(
        "did:nostr:{}",
        hex::encode(signing.verifying_key().to_bytes())
    );
    let url = "http://pod.example/private/document.txt";
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let sign = |body: Option<&[u8]>| {
        nip98::authorization_header(
            &nip98::mint_with_payload(url, "PUT", body, &secret, now).unwrap(),
        )
    };
    let storage = Arc::new(MemoryBackend::new());
    storage.create_container("/private/").await.unwrap();
    let acl = format!(
        r#"@prefix acl: <http://www.w3.org/ns/auth/acl#> .
<#owner> a acl:Authorization; acl:agent <{did}>; acl:accessTo </private/>; acl:default </private/>; acl:mode acl:Read, acl:Write, acl:Control ."#
    );
    storage
        .put("/private.acl", Bytes::from(acl), "text/turtle")
        .await
        .unwrap();
    storage
        .put(
            "/private/document.txt",
            Bytes::from_static(b"original"),
            "text/plain",
        )
        .await
        .unwrap();
    let app = test::init_service(build_app(AppState::new(storage.clone()))).await;
    let request = |body: &'static [u8], auth: Option<&str>| {
        let mut r = test::TestRequest::put()
            .uri("/private/document.txt")
            .insert_header(("host", "pod.example"))
            .insert_header(("content-type", "text/plain"));
        if let Some(a) = auth {
            r = r.insert_header(("authorization", a));
        }
        r.set_payload(Bytes::from_static(body)).to_request()
    };
    let denied = |status| {
        assert!(
            status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN,
            "expected authentication refusal: {status}"
        )
    };
    // Positive control before any rejection assertion.
    let control = sign(Some(b"original"));
    assert!(
        test::call_service(&app, request(b"original", Some(&control)))
            .await
            .status()
            .is_success()
    );
    denied(test::call_service(&app, request(b"", None)).await.status());
    let unbound = sign(None);
    denied(
        test::call_service(&app, request(b"", Some(&unbound)))
            .await
            .status(),
    );
    let token = sign(Some(b"intended"));
    for body in [b"altered".as_slice(), b"".as_slice()] {
        denied(
            test::call_service(&app, request(body, Some(&token)))
                .await
                .status(),
        );
        assert_eq!(
            &storage.get("/private/document.txt").await.unwrap().0[..],
            b"original"
        );
    }
    // Invalid bodies did not spend the intended token.
    assert!(test::call_service(&app, request(b"intended", Some(&token)))
        .await
        .status()
        .is_success());
    assert_eq!(
        &storage.get("/private/document.txt").await.unwrap().0[..],
        b"intended"
    );
    denied(
        test::call_service(&app, request(b"intended", Some(&token)))
            .await
            .status(),
    );
    // A deliberate empty write uses the hash of empty bytes and still works.
    let empty = sign(Some(b""));
    assert!(test::call_service(&app, request(b"", Some(&empty)))
        .await
        .status()
        .is_success());
    assert!(storage
        .get("/private/document.txt")
        .await
        .unwrap()
        .0
        .is_empty());
    denied(
        test::call_service(&app, request(b"", Some(&empty)))
            .await
            .status(),
    );
}
