#![no_main]
use libfuzzer_sys::fuzz_target;
use tecdsa_core::{
    keygen::{ClientKeyShare, ServerKeyShare},
    params::{PARAMS_112, PARAMS_128},
    setup::SetupData,
};

fuzz_target!(|data: &[u8]| {
    for p in [PARAMS_128, PARAMS_112] {
        // Parsing only: proof verification is exercised by the unit tests.
        let _ = SetupData::from_bytes(data, &p);
        let _ = ClientKeyShare::import_secret(data, &p);
        let _ = ServerKeyShare::import_secret(data, &p);
    }
});
