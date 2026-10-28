//! Deterministic regression vectors (reduced profile, fixed seeds): `vectors/reduced.json`.
//! Any change of the wire format or the protocol arithmetic changes these digests on purpose.
//! Regenerate with `TECDSA_UPDATE_VECTORS=1 cargo test --release --lib vectors`.
extern crate std;

use core::cell::Cell;
use rand_chacha::ChaCha8Rng;
use rand_core::SeedableRng;
use sha2::{Digest, Sha256};
use std::{fmt::Write, string::String};

use crate::{
    curve::encode_point,
    keygen::{ClientKeygen0, ServerKeygen0},
    sign::{ClientSign, ServerSign0},
    testutil::{TestClock, fx, params},
};

fn hex(b: &[u8]) -> String {
    b.iter().fold(String::new(), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    })
}

fn sha(b: &[u8]) -> String {
    hex(&Sha256::digest(b))
}

fn render() -> String {
    let p = params();
    let mut rng = ChaCha8Rng::seed_from_u64(0xEC_D5A);
    let clock = TestClock(Cell::new(1_000));
    let setup_bytes = fx().data.to_bytes().unwrap();
    let (s1, kg1) = ServerKeygen0::start(&mut rng, &p, &fx().data, b"client-1").unwrap();
    let (c1, kg2) =
        ClientKeygen0::on_msg1(&mut rng, &clock, &fx().setup, b"client-1", &kg1).unwrap();
    let (server_share, kg3) = s1.on_msg2(&mut rng, &kg2).unwrap();
    let client_share = c1.on_msg3(&clock, &kg3).unwrap();
    let digest: [u8; 32] = Sha256::digest(b"tecdsa test vector message").into();
    let (st, sg1) = ServerSign0::start(
        &mut rng,
        &fx().server_view,
        &server_share,
        b"client-1",
        &digest,
    )
    .unwrap();
    let sg2 = ClientSign::respond(
        &mut rng,
        &fx().setup,
        &client_share,
        b"client-1",
        &digest,
        &sg1,
    )
    .unwrap();
    let (sig, sg3) = st
        .finish(&fx().server_view, fx().sk.paillier_sk(), &sg2)
        .unwrap();
    let mut o = String::from("{\n");
    let mut kv = |k: &str, v: &str, last: bool| {
        let _ = writeln!(o, "  \"{k}\": \"{v}\"{}", if last { "" } else { "," });
    };
    kv(
        "profile",
        "reduced (see testutil::params), seeds: setup 1, session 0xECD5A",
        false,
    );
    kv("setup_sha256", &sha(&setup_bytes), false);
    kv("kg_msg1_hex", &hex(&kg1), false);
    kv("kg_msg2_sha256", &sha(&kg2), false);
    kv("kg_msg3_sha256", &sha(&kg3), false);
    kv(
        "public_key",
        &hex(&encode_point(client_share.public_key())),
        false,
    );
    kv("key_id", &hex(&client_share.key_id()), false);
    kv("digest", &hex(&digest), false);
    kv("sign_msg1_hex", &hex(&sg1), false);
    kv("sign_msg2_sha256", &sha(&sg2), false);
    kv("sign_msg3_hex", &hex(&sg3), false);
    kv("signature_rs", &hex(&sig.to_bytes()), false);
    kv("recid", &std::format!("{}", sig.recid), true);
    o.push_str("}\n");
    o
}

#[test]
fn vectors_match_committed_file() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../vectors/reduced.json");
    let got = render();
    if std::env::var("TECDSA_UPDATE_VECTORS").is_ok() {
        std::fs::create_dir_all(concat!(env!("CARGO_MANIFEST_DIR"), "/../vectors")).unwrap();
        std::fs::write(path, &got).unwrap();
    }
    let want =
        std::fs::read_to_string(path).expect("vectors/reduced.json (set TECDSA_UPDATE_VECTORS=1)");
    assert_eq!(got, want);
    assert_eq!(render(), got, "generation must be deterministic");
}
