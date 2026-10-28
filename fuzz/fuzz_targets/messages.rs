#![no_main]
use libfuzzer_sys::fuzz_target;
use tecdsa_core::{curve, messages::*, params::PARAMS_128};

fuzz_target!(|data: &[u8]| {
    let p = PARAMS_128;
    let _ = KgMsg1::decode(data, &p);
    let _ = KgMsg2::decode(data, &p);
    let _ = KgMsg3::decode(data, &p);
    let _ = SignMsg1::decode(data, &p);
    let _ = SignMsg2::decode(data, &p);
    let _ = SignMsg3::decode(data, &p);
    let _ = curve::decode_point(data);
    let _ = curve::decode_scalar(data);
});
