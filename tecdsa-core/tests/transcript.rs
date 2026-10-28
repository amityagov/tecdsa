//! Transcript determinism, separation and challenge ranges.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use crypto_bigint::BoxedUint;
use tecdsa_core::{
    arith::{Modulus, sbig::SRange},
    transcript::{Transcript, uint_from_be, uint_to_be},
};

#[test]
fn deterministic_and_separated() {
    let mk = |domain: &str, label: &str, data: &[u8]| {
        let mut t = Transcript::new(domain);
        t.append(label, data);
        t.challenge("c").seed()
    };
    assert_eq!(mk("zk/sig", "a", b"x"), mk("zk/sig", "a", b"x"));
    assert_ne!(mk("zk/sig", "a", b"x"), mk("zk/dlenc", "a", b"x"));
    assert_ne!(mk("zk/sig", "a", b"x"), mk("zk/sig", "b", b"x"));
    assert_ne!(mk("zk/sig", "a", b"x"), mk("zk/sig", "a", b"y"));
    // length framing: ("ab","c") ≠ ("a","bc")
    let mut t1 = Transcript::new("d");
    t1.append("ab", b"c");
    let mut t2 = Transcript::new("d");
    t2.append("a", b"bc");
    assert_ne!(t1.challenge("c").seed(), t2.challenge("c").seed());
    // challenge does not advance the transcript
    let t = Transcript::new("d");
    assert_eq!(t.challenge("c").seed(), t.challenge("c").seed());
    assert_ne!(t.challenge("c").seed(), t.challenge("d").seed());
}

#[test]
fn challenge_ranges() {
    let mut t = Transcript::new("r");
    let mut ch = t.append("x", b"1").challenge("e");
    let range = SRange::pm_pow2(128);
    let (mut neg, mut pos) = (0, 0);
    for _ in 0..2000 {
        let e = ch.pm_pow2(128);
        assert!(e.in_range(range));
        if bool::from(e.is_neg()) {
            neg += 1
        } else {
            pos += 1
        }
    }
    assert!(neg > 800 && pos > 800);
    for _ in 0..100 {
        assert!(ch.small(8) < 256);
        assert!(ch.bits(70).bits() <= 70);
    }
}

#[test]
fn unit_and_qr_challenges() {
    let m = Modulus::new(BoxedUint::from(3u64 * 5 * 7 * 11 * 13 * 17)).unwrap();
    let mut ch = Transcript::new("u").challenge("y");
    for _ in 0..50 {
        let y = ch.unit_mod(&m).unwrap().retrieve();
        let v = y.as_words()[0];
        assert!([3, 5, 7, 11, 13, 17].iter().all(|p| v % p != 0));
    }
    let p = Modulus::new(BoxedUint::from(1_000_003u64)).unwrap();
    for _ in 0..50 {
        let g = ch.qr_mod(&p).unwrap().retrieve().as_words()[0];
        assert!(g > 1);
    }
}

#[test]
fn uint_codec() {
    let x = BoxedUint::from(0x0102_0304u64);
    assert_eq!(uint_to_be(&x, 6).unwrap(), [0, 0, 1, 2, 3, 4]);
    assert!(uint_to_be(&x, 3).is_err());
    assert_eq!(
        uint_from_be(&[0, 0, 1, 2, 3, 4], 64).unwrap(),
        BoxedUint::from(0x0102_0304u64)
    );
}
