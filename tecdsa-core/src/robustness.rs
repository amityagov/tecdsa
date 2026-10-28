//! Deterministic mutation smoke test: every parser and every protocol entry point must return
//! an error (never panic, hang or accept) on mangled input. The libFuzzer targets in `fuzz/`
//! cover the same entry points for long runs.
extern crate std;

use core::cell::Cell;
use rand_chacha::ChaCha8Rng;
use rand_core::{Rng, SeedableRng};
use std::vec::Vec;

use crate::{
    keygen::{ClientKeyShare, ClientKeygen0, ServerKeyShare, ServerKeygen0},
    setup::SetupData,
    sign::{ClientSign, ServerSign0},
    testutil::{TestClock, fx, keygen, params},
};

fn mutate(rng: &mut ChaCha8Rng, src: &[u8]) -> Vec<u8> {
    let mut v = src.to_vec();
    match rng.next_u32() % 6 {
        0 => {
            // flip a few bits
            for _ in 0..=rng.next_u32() % 4 {
                if !v.is_empty() {
                    let i = rng.next_u32() as usize % v.len();
                    v[i] ^= 1 << (rng.next_u32() % 8);
                }
            }
        }
        1 => v.truncate(rng.next_u32() as usize % (v.len() + 1)),
        2 => {
            let extra = 1 + rng.next_u32() as usize % 16;
            let mut tail = std::vec![0u8; extra];
            rng.fill_bytes(&mut tail);
            v.extend(tail);
        }
        3 => {
            // overwrite a run with 0x00 / 0xFF
            if !v.is_empty() {
                let i = rng.next_u32() as usize % v.len();
                let n = (1 + rng.next_u32() as usize % 40).min(v.len() - i);
                let b = if rng.next_u32() & 1 == 0 { 0 } else { 0xFF };
                v[i..i + n].fill(b);
            }
        }
        4 => {
            // random bytes of the same length
            rng.fill_bytes(&mut v);
        }
        _ => {
            // splice: duplicate a chunk
            if v.len() > 4 {
                let i = rng.next_u32() as usize % (v.len() - 2);
                let n = 1 + rng.next_u32() as usize % (v.len() - i).min(64);
                let chunk = v[i..i + n].to_vec();
                v.splice(i..i, chunk);
            }
        }
    }
    v
}

const ROUNDS: usize = 150;

#[test]
fn mangled_keygen_and_setup_never_panic_or_verify() {
    let p = params();
    let mut rng = ChaCha8Rng::seed_from_u64(900);
    let clock = TestClock(Cell::new(1_000));
    let (s1, m1) = ServerKeygen0::start(&mut rng, &p, &fx().data, b"c").unwrap();
    let (c1, m2) = ClientKeygen0::on_msg1(&mut rng, &clock, &fx().setup, b"c", &m1).unwrap();
    let (_, m3) = s1.on_msg2(&mut rng, &m2).unwrap();
    let _ = c1;

    for _ in 0..ROUNDS {
        let bad1 = mutate(&mut rng, &m1);
        if bad1 != m1 {
            // KgMsg1 carries opaque random values, so the client may accept it at step 2; the
            // session must then fail at a later step because the server's state differs.
            let (s1, m1) = ServerKeygen0::start(&mut rng, &p, &fx().data, b"c").unwrap();
            let bad1 = mutate(&mut rng, &m1);
            if bad1 != m1 {
                let done = ClientKeygen0::on_msg1(&mut rng, &clock, &fx().setup, b"c", &bad1)
                    .and_then(|(c1, m2)| {
                        let (_, m3) = s1.on_msg2(&mut rng, &m2)?;
                        c1.on_msg3(&clock, &m3)
                    });
                assert!(done.is_err());
            }
        }
        let bad2 = mutate(&mut rng, &m2);
        if bad2 != m2 {
            let (s1, _) = ServerKeygen0::start(&mut rng, &p, &fx().data, b"c").unwrap();
            assert!(s1.on_msg2(&mut rng, &bad2).is_err());
        }
        let bad3 = mutate(&mut rng, &m3);
        if bad3 != m3 {
            let (s1, m1) = ServerKeygen0::start(&mut rng, &p, &fx().data, b"c").unwrap();
            let (c1, _) = ClientKeygen0::on_msg1(&mut rng, &clock, &fx().setup, b"c", &m1).unwrap();
            let _ = s1;
            // a message of another session never verifies
            assert!(c1.on_msg3(&clock, &bad3).is_err());
        }
    }

    // setup bytes: parsing must not panic; mangled data must not verify
    let bytes = fx().data.to_bytes().unwrap();
    for _ in 0..40 {
        let bad = mutate(&mut rng, &bytes);
        if bad == bytes {
            continue;
        }
        if let Ok(d) = SetupData::from_bytes_with(&bad, &p, &fx().fac) {
            assert!(d.verify_with(&p, &fx().fac).is_err());
        }
    }
}

#[test]
fn mangled_signing_and_secrets_never_panic_or_verify() {
    let p = params();
    let mut rng = ChaCha8Rng::seed_from_u64(901);
    let (c, s) = keygen(60);
    let d = [5u8; 32];
    let (st, m1) = ServerSign0::start(&mut rng, &fx().server_view, &s, b"c", &d).unwrap();
    let m2 = ClientSign::respond(&mut rng, &fx().setup, &c, b"c", &d, &m1).unwrap();
    let _ = st;

    for _ in 0..ROUNDS {
        let bad1 = mutate(&mut rng, &m1);
        if bad1 != m1 {
            assert!(ClientSign::respond(&mut rng, &fx().setup, &c, b"c", &d, &bad1).is_err());
        }
        let bad2 = mutate(&mut rng, &m2);
        if bad2 != m2 {
            let (st, m1b) = ServerSign0::start(&mut rng, &fx().server_view, &s, b"c", &d).unwrap();
            let _ = m1b;
            assert!(
                st.finish(&fx().server_view, fx().sk.paillier_sk(), &bad2)
                    .is_err()
            );
        }
    }

    // exported secrets: import must reject or return a share that is not the original
    let cs = c.export_secret();
    let ss = s.export_secret();
    for _ in 0..60 {
        let bad = mutate(&mut rng, &cs);
        if bad.as_slice() != cs.as_slice() {
            if let Ok(x) = ClientKeyShare::import_secret(&bad, &p) {
                assert_ne!(x.export_secret().as_slice(), cs.as_slice());
            }
        }
        let bad = mutate(&mut rng, &ss);
        if bad.as_slice() != ss.as_slice() {
            if let Ok(x) = ServerKeyShare::import_secret(&bad, &p) {
                assert_ne!(x.export_secret().as_slice(), ss.as_slice());
            }
        }
    }
}
