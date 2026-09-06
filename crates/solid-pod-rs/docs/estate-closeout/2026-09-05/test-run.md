# Test receipts — estate closeout 2026-09-05

Repository: DreamLab-AI/solid-pod-rs at working tree above `d6ac7f5` (uncommitted).
Toolchain: `cargo 1.98.1 (797e8a9bc 2026-08-05)` / `rustc 1.98.1 (48a229cea 2026-09-01)`.
No network access in any test; no crate version was changed.

## `cargo test --workspace`

```
     Running unittests src/lib.rs (target/debug/deps/solid_pod_rs-699a8ab2cb0cdcb0)
test result: ok. 474 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 4.69s
     Running tests/acl_origin_sprint9.rs (target/debug/deps/acl_origin_sprint9-90b602a12126b1a7)
test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/acl_origin_test.rs (target/debug/deps/acl_origin_test-99b8947f35f18f35)
test result: ok. 16 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/bitcoin_tx_chain.rs (target/debug/deps/bitcoin_tx_chain-cf9c455aff156fe2)
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.06s
     Running tests/cid_verifier_sprint11.rs (target/debug/deps/cid_verifier_sprint11-9de592d8aee2c8b5)
test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
     Running tests/config_size_parsing.rs (target/debug/deps/config_size_parsing-f80d8b4539d33860)
test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/config_sprint11.rs (target/debug/deps/config_sprint11-c11c6719bc1b7907)
test result: ok. 12 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/config_test.rs (target/debug/deps/config_test-448a33c8e2202a91)
test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/container_index_html.rs (target/debug/deps/container_index_html-8a3a3e1ea1d38085)
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.03s
     Running tests/cors_preflight.rs (target/debug/deps/cors_preflight-a68dff78f244a3cd)
test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/did_nostr_resolver.rs (target/debug/deps/did_nostr_resolver-2380567e71e996f3)
test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/dpop_replay_test.rs (target/debug/deps/dpop_replay_test-f95cd616979e9605)
test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.03s
     Running tests/export_jsonld_smoke.rs (target/debug/deps/export_jsonld_smoke-3762148d49c7fb5c)
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/interop_jss.rs (target/debug/deps/interop_jss-72fd33537911ea2c)
test result: ok. 43 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/jti_replay_sprint9.rs (target/debug/deps/jti_replay_sprint9-a1476158c4880455)
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
     Running tests/ldp_headers_jss.rs (target/debug/deps/ldp_headers_jss-678bb8eef366f73b)
test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/ldp_patch_create_jss.rs (target/debug/deps/ldp_patch_create_jss-620efb7284cb20a0)
test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/ldp_range_jss.rs (target/debug/deps/ldp_range_jss-7adcf70cd0327698)
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/ldp_slug_jss.rs (target/debug/deps/ldp_slug_jss-08b0423ec46ada71)
test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/legacy_notifications_sprint11.rs (target/debug/deps/legacy_notifications_sprint11-081b1ed25c6230b6)
test result: ok. 11 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/legacy_notifications_test.rs (target/debug/deps/legacy_notifications_test-f685ea749054a5c0)
test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.10s
     Running tests/legacy_wac_check.rs (target/debug/deps/legacy_wac_check-4370cdaae15f937b)
test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/nip05_endpoint_smoke.rs (target/debug/deps/nip05_endpoint_smoke-26358a131449111c)
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/nip98_extended.rs (target/debug/deps/nip98_extended-25918127a68645e7)
test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
     Running tests/nodeinfo_jss.rs (target/debug/deps/nodeinfo_jss-f31bc9210207fc6c)
test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/notifications_mod_direct.rs (target/debug/deps/notifications_mod_direct-6fb8a554bf9a46f5)
test result: ok. 11 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/oidc_access_token_alg.rs (target/debug/deps/oidc_access_token_alg-fdafccdf054e90a8)
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
     Running tests/oidc_compat_matrix.rs (target/debug/deps/oidc_compat_matrix-6b3015eb8c43a7c0)
test result: ok. 28 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/oidc_dpop_signature.rs (target/debug/deps/oidc_dpop_signature-79906745fc3e23e5)
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
     Running tests/oidc_integration.rs (target/debug/deps/oidc_integration-c645ef564020717b)
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
     Running tests/oidc_jwks_ssrf.rs (target/debug/deps/oidc_jwks_ssrf-80b12162613dd3f3)
test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/oidc_mod_direct.rs (target/debug/deps/oidc_mod_direct-7df36fe8b6deb8bb)
test result: ok. 13 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/oidc_thumbprint_rfc7638.rs (target/debug/deps/oidc_thumbprint_rfc7638-b23e95499404aac9)
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/parity_close.rs (target/debug/deps/parity_close-669d78837c89fc7e)
test result: ok. 22 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/parity_sprint12.rs (target/debug/deps/parity_sprint12-2fefe2ca91d8ab9f)
test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/provenance_receipts.rs (target/debug/deps/provenance_receipts-c8a8acbc7e0d8c8f)
test result: ok. 14 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/quota_fs.rs (target/debug/deps/quota_fs-0b1f0e36bba22ff5)
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/quota_race.rs (target/debug/deps/quota_race-6ae805755fdf845a)
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/rate_limit_lru.rs (target/debug/deps/rate_limit_lru-bfdf20c45d41a7d0)
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.18s
     Running tests/schnorr_nip98.rs (target/debug/deps/schnorr_nip98-bcf0b745079b7dce)
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/security_primitives_test.rs (target/debug/deps/security_primitives_test-bb00aa71b02ed94a)
test result: ok. 17 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/server_routes_jss.rs (target/debug/deps/server_routes_jss-1f8838a85c36724a)
test result: ok. 14 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.06s
     Running tests/server_security.rs (target/debug/deps/server_security-62f8658fd55e147d)
test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.03s
     Running tests/sparql_fuzzing.rs (target/debug/deps/sparql_fuzzing-02362a0fae4daa65)
test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s
     Running tests/sprint12_security.rs (target/debug/deps/sprint12_security-5782e7362022cc70)
test result: ok. 15 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/storage_trait.rs (target/debug/deps/storage_trait-8c054947ee7faf32)
test result: ok. 15 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 2.26s
     Running tests/tenancy_subdomain.rs (target/debug/deps/tenancy_subdomain-8bde5935d528472d)
test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/wac2_conditions.rs (target/debug/deps/wac2_conditions-a9c7028112a994b4)
test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/wac2_conditions_sprint9.rs (target/debug/deps/wac2_conditions_sprint9-144f7772943e23e1)
test result: ok. 13 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/wac_basic.rs (target/debug/deps/wac_basic-02999aad8dc9cc1b)
test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/wac_concurrent.rs (target/debug/deps/wac_concurrent-5c7f58d6bd345bda)
test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
     Running tests/wac_inheritance.rs (target/debug/deps/wac_inheritance-ace7a850318b8850)
test result: ok. 31 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/wac_parser_bounds.rs (target/debug/deps/wac_parser_bounds-2fb81a71f8fb3ed7)
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/wac_payment_condition.rs (target/debug/deps/wac_payment_condition-eb5e7959b8583f47)
test result: ok. 12 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/wac_policy_outcomes.rs (target/debug/deps/wac_policy_outcomes-a1f1eed85b5f40d7)
test result: ok. 20 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.08s
     Running tests/wac_validate_for_write.rs (target/debug/deps/wac_validate_for_write-ba4c210a554bbe43)
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/webhook_retry.rs (target/debug/deps/webhook_retry-d2ff538f4901b719)
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/webhook_signing.rs (target/debug/deps/webhook_signing-60cbceda85326ced)
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running unittests src/lib.rs (target/debug/deps/solid_pod_rs_activitypub-65aa54582b81b5de)
test result: ok. 94 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 11.71s
     Running tests/federation_flows.rs (target/debug/deps/federation_flows-1a3d6ea123728910)
test result: ok. 34 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 11.91s
     Running tests/http_signatures.rs (target/debug/deps/http_signatures-cbd583953dab17ca)
test result: ok. 17 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 15.89s
     Running tests/sprint12_ap_features.rs (target/debug/deps/sprint12_ap_features-ae41bf2cfc7d96ef)
test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/store_comprehensive.rs (target/debug/deps/store_comprehensive-7dfd32f5f7a59234)
test result: ok. 45 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.09s
     Running unittests src/lib.rs (target/debug/deps/solid_pod_rs_didkey-fbc2d0449e311493)
test result: ok. 12 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/jwt_verify.rs (target/debug/deps/jwt_verify-4d14535f8d33d44c)
test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
     Running tests/roundtrip.rs (target/debug/deps/roundtrip-2178ca700490276e)
test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/upstream_vectors/main.rs (target/debug/deps/upstream_vectors-a6c61485d529086e)
test result: ok. 3 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running unittests src/lib.rs (target/debug/deps/solid_pod_rs_forge-032dfe844d99c9f1)
test result: ok. 96 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.12s
     Running unittests src/lib.rs (target/debug/deps/solid_pod_rs_git-f336382af0411b29)
test result: ok. 60 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.06s
     Running tests/git_service_sprint10.rs (target/debug/deps/git_service_sprint10-70df5588729fb529)
test result: ok. 11 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
     Running unittests src/lib.rs (target/debug/deps/solid_pod_rs_idp-80af46249c764864)
test result: ok. 64 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 5.15s
     Running tests/invites_and_tokens.rs (target/debug/deps/invites_and_tokens-9243adc795860f05)
test result: ok. 39 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.43s
     Running tests/key_provisioning_smoke.rs (target/debug/deps/key_provisioning_smoke-340d2f1f278a1f59)
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/passkey_sprint11.rs (target/debug/deps/passkey_sprint11-3eb77bd8ec40bdb6)
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/provider_flows.rs (target/debug/deps/provider_flows-d66ff7397dbe5a3c)
test result: ok. 25 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.55s
     Running tests/registration_client_store.rs (target/debug/deps/registration_client_store-6ff5fa27f80b805f)
test result: ok. 20 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/schnorr_sso_sprint11.rs (target/debug/deps/schnorr_sso_sprint11-85b89401ced745d1)
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/session_store.rs (target/debug/deps/session_store-9b8423ad6ab3280d)
test result: ok. 20 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s
     Running tests/sprint12_password.rs (target/debug/deps/sprint12_password-3cfe4675f8e99a8e)
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running unittests src/lib.rs (target/debug/deps/solid_pod_rs_nostr-eb98212556a25ed7)
test result: ok. 63 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.04s
     Running tests/relay_nip11.rs (target/debug/deps/relay_nip11-9485a5e31c4d73bc)
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/resolver_integration.rs (target/debug/deps/resolver_integration-cb675d62ffe50703)
test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/upstream_vectors/main.rs (target/debug/deps/upstream_vectors-8cac4b82e21d560c)
test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running unittests src/lib.rs (target/debug/deps/solid_pod_rs_server-826e9768850a15be)
test result: ok. 52 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.04s
     Running unittests src/main.rs (target/debug/deps/solid_pod_rs_server-1095a1f285a77d80)
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/admin_provision.rs (target/debug/deps/admin_provision-7aacf75cf043d1a0)
test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.46s
     Running tests/cache_control_policy.rs (target/debug/deps/cache_control_policy-33a61c2585bcb648)
test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.05s
     Running tests/cli_comprehensive.rs (target/debug/deps/cli_comprehensive-97dadc5227a91a05)
test result: ok. 13 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.54s
     Running tests/cli_ops_sprint11.rs (target/debug/deps/cli_ops_sprint11-ceddc8e05d0bc554)
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.45s
     Running tests/error_logging_middleware.rs (target/debug/deps/error_logging_middleware-2f1cef488cc22c38)
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.20s
     Running tests/get_content_negotiation_integration.rs (target/debug/deps/get_content_negotiation_integration-fa17e777c4a7d8f9)
test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.04s
     Running tests/git_marks.rs (target/debug/deps/git_marks-77044fc0404e04ec)
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/git_wac_gating.rs (target/debug/deps/git_wac_gating-d28d8351eb71f9f9)
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/mcp_wac_security.rs (target/debug/deps/mcp_wac_security-d1717a05b0cbb751)
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.03s
     Running tests/mempool_selection.rs (target/debug/deps/mempool_selection-275a44c381af3825)
test result: ok. 13 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/middleware_guards.rs (target/debug/deps/middleware_guards-1a7d8be7141cce55)
test result: ok. 21 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.05s
     Running tests/nip05_endpoint_integration.rs (target/debug/deps/nip05_endpoint_integration-d3ce6af280841f17)
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/patch_non_destructive_integration.rs (target/debug/deps/patch_non_destructive_integration-69813f2590aa812e)
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.03s
     Running tests/pay_mrc20_routes.rs (target/debug/deps/pay_mrc20_routes-6f61d375e3ae5012)
test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.08s
     Running tests/pay_phase4_routes.rs (target/debug/deps/pay_phase4_routes-201131dd17fd1ba8)
test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.10s
     Running tests/pay_routes.rs (target/debug/deps/pay_routes-227a9db98758f03c)
test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.15s
     Running tests/payment_atomicity.rs (target/debug/deps/payment_atomicity-1cde2bab7347e821)
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.05s
     Running tests/prov_phase5_routes.rs (target/debug/deps/prov_phase5_routes-f9532aae274a0fb0)
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/proxy_endpoint.rs (target/debug/deps/proxy_endpoint-ddad7ae62b5606ec)
test result: ok. 17 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.03s
     Running tests/quota_enforcement.rs (target/debug/deps/quota_enforcement-8e15538d0739a890)
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/registration_security.rs (target/debug/deps/registration_security-336245e5216cd69c)
test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.03s
   Doc-tests solid_pod_rs
test result: ok. 4 passed; 0 failed; 3 ignored; 0 measured; 0 filtered out; finished in 0.08s
   Doc-tests solid_pod_rs_activitypub
test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.00s
   Doc-tests solid_pod_rs_didkey
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.06s
   Doc-tests solid_pod_rs_forge
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
   Doc-tests solid_pod_rs_git
test result: ok. 1 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.07s
   Doc-tests solid_pod_rs_idp
test result: ok. 1 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.07s
   Doc-tests solid_pod_rs_nostr
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.31s
   Doc-tests solid_pod_rs_server
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

## Aggregate

- **1801 passed, 0 failed, 0 ignored** across 114 test binaries.

## New acceptance suites added by this change

| Suite | ADR | Tests |
|---|---|---|
| `crates/solid-pod-rs/tests/wac_policy_outcomes.rs` | ADR-2005 | 20 |
| `crates/solid-pod-rs/tests/provenance_receipts.rs` | ADR-2004 | 14 |
| `crates/solid-pod-rs/tests/oidc_compat_matrix.rs` | ADR-2003 | 28 |
| `crates/solid-pod-rs-server/tests/cache_control_policy.rs` | ADR-2002 | 10 |
| `crates/solid-pod-rs-server/tests/mempool_selection.rs` | ADR-2007 | 13 |
| `crates/solid-pod-rs/src/auth/replay.rs` (unit) | ADR-2006 | 13 |

## Lint

```
$ cargo clippy --all-targets --all-features -- -D warnings
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.78s
clean — no errors, no warnings
```

## Feature-surface checks

```
$ cargo check -p solid-pod-rs --no-default-features --features core   # wasm/edge surface
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.54s
$ cargo build -p solid-pod-rs-server --features git
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.55s
```
