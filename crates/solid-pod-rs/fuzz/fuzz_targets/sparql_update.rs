#![no_main]

use libfuzzer_sys::fuzz_target;
use solid_pod_rs::ldp::{apply_sparql_patch, Graph, SPARQL_UPDATE_MAX_BYTES};

fuzz_target!(|data: &[u8]| {
    // Only attempt to parse inputs that are valid UTF-8 and within the
    // size cap. The size cap itself is the first line of defence against
    // DoS; the fuzzer should exercise inputs below the cap to surface
    // panics in the spargebra parser path.
    let input = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return,
    };

    if input.len() > SPARQL_UPDATE_MAX_BYTES {
        // The library rejects oversized inputs with an Err — verify it
        // does not panic.
        let result = apply_sparql_patch(Graph::new(), input);
        assert!(result.is_err(), "oversized input should be rejected");
        return;
    }

    // For inputs within the size limit, the parser must either succeed
    // or return an error — never panic.
    let _ = apply_sparql_patch(Graph::new(), input);
});
