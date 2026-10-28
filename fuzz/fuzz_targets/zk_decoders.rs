#![no_main]
use libfuzzer_sys::fuzz_target;
use tecdsa_core::{
    params::PARAMS_128,
    zk::{df_star::DfStarProof, dlenc::DlencProof, dlog::DlogProof, sig::SigProof},
};

fuzz_target!(|data: &[u8]| {
    let p = PARAMS_128;
    let _ = DlogProof::decode(data, &p);
    let _ = DfStarProof::decode(data, &p);
    let _ = DlencProof::decode(data, &p);
    let _ = SigProof::decode(data, &p);
});
