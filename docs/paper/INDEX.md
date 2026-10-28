# Index of docs/paper/1950.txt (text extracted from 1950.pdf; page markers "=====PAGE n=====")

Sources, cheapest first:
1. `1950.txt` - plain text (pypdf); superscripts/hats are flattened ("22ℓ" = 2^{2ℓ}).
2. `1950.layout.txt` - poppler `-layout` text; sub/superscripts sit on separate lines, formulas somewhat clearer. Page breaks are form feeds.
3. `pages/p-NN.png` - 100 dpi page images (git-ignored, regenerate: `pdftoppm -r 100 -png 1950.pdf docs/paper/pages/p`). Use these to verify any formula/equation before coding it (ZK verifier equations especially).

Format: line number | PDF page | heading. Search with grep, read ranges with Read offset/limit.

34 | p2 | 1 Introduction 1
42 | p2 | 2 T echnical Overview 8
55 | p2 | 3 Preliminaries 21
72 | p3 | 5 Underlying ZK Protocols 33
83 | p3 | 6 Security Analysis 44
90 | p3 | 7 Unforgeability in the Generic Group Model 60
98 | p3 | 8 Benchmarks 70
113 | p4 | 1 Introduction
138 | p4 | 1.1 Efficiency requirements for 2-party ECDSA
173 | p5 | 1.2 Our Contribution
294 | p8 | 1.3 Comparison to the state-of-the-art
427 | p11 | 1.4 Organization
438 | p11 | 2 Technical Overview
461 | p12 | 2.1 ECDSA at the Cost of 1 OLE
473 | p12 | Protocol Our 2-Party ECDSA Signing Protocol
495 | p13 | Protocol 1: 2-Party ECDSA at the cost of 1 OLE.
508 | p13 | 2.1.1 Sketch security Analysis
584 | p15 | 2.2 Doubly-Enhanced Existential Unforgeability of ECDSA
613 | p15 | Theorem 2.1 (Informal). Let A denote a generic attacker making at most t group operations
630 | p16 | 2.2.1 The generic group model
645 | p16 | 2.2.2 Sketch security proof
723 | p18 | 2.3 Implementation using Paillier Encryption and Integer Commitments
756 | p19 | 2.3.1 Efficiency considerations
771 | p19 | 2.3.2 T ough primes optimization
784 | p20 | Algorithm Sampling tough-prime RSA moduli
792 | p20 | Algorithm 1: Protocol for sampling tough primes
834 | p21 | 2.3.3 F ast and compact variant of Damg ˚ ard-F ujisaki parameters proof
841 | p21 | Protocol Vanilla Damg ˚ ard-Fujisaki parameters well-formedness proof
878 | p22 | 2.3.4 Systematic use of small-exponents
914 | p23 | 2.3.5 Dealing with the cheating subgroup problem
958 | p24 | 2.3.6 Applications to embedded cryptocurrency wallets
974 | p24 | 3 Preliminaries
975 | p24 | 3.1 Notation
1019 | p25 | 3.2 Standard Lemmas
1020 | p25 | Lemma 3.1 (Generalized Forking Lemma [BN06]). Fix a bound Q ≥ 1 and a set S of size |S| ≥2
1032 | p26 | Algorithm FA(x)
1050 | p26 | Algorithm 2: Forking algorithm associated to A.
1051 | p26 | 3.3 Security Assumptions
1056 | p26 | Definition 3.2 (FAC). Define distribution ensemble FAC such that N
1067 | p26 | Definition 3.3 (SRSA). Define distribution ensemble SRSA such that ( N, c)
1080 | p26 | Definition 3.4 (SEDL over Z∗N ). Define SEDL such that ( N, t,[tx]N ) $← SEDL(1ℓ) for ( N 
1091 | p27 | Definition 3.5 (SEI over Z∗N ). Define distribution ensemble SEI such that (N, t,[tαx+(1−α
1101 | p27 | 3.3.1 DCR V ariants
1102 | p27 | Definition 3.6 (DCR). Define DCR such that ( N, [ραN · c1−α]N 2, α) $← DCR(1ℓ) for N $←
1112 | p27 | Definition 3.7 (QRDCR). Define QRDCR such that ( N, [ραN · c1−α]N 2, α) $← QRDCR(1ℓ) for
1123 | p27 | Definition 3.8 (SEDCR). Define SEDCR such that ( N, ρ0, [ραλN0 · c1−α]N 2, α) $← SEDCR(1ℓ)
1166 | p28 | 3.3.2 Damg ˚ ard-F ujisaki to Strong-RSA reduction
1167 | p28 | Definition 3.10 (Tough RSA moduli) . Let N = pq denote an RSA modulus. For ℓ ∈ N, we say
1173 | p28 | Lemma 3.12. Let N denote a 2ℓ-tough RSA modulus and let g ∈ QRN such that ⟨g⟩ = QRN .
1234 | p29 | 3.4 Paillier Encryption, Damg ˚ ard-Fujisaki & Pedersen Commitments
1235 | p29 | Definition 3.14. Paillier Encryption consists of the following algorithms.
1255 | p30 | Definition 3.15. Damg ˚ ard-Fujisaki commitments in RSA groups consist of the following al
1261 | p30 | Definition 3.16. Pedersen Commitments in a known-order group ( G, g, h, f, q) where ⟨g⟩ = 
1267 | p30 | 3.5 Zero-Knowledge Proofs
1280 | p30 | 3.5.1 NIZK and the Fiat-Shamir T ransform
1291 | p30 | 3.5.2 NP Relations
1293 | p30 | Definition 3.17 (Well-Formed Modulus). Define Rmod ∋ (N ; p1, p2) such that N = p1 · p2 wh
1295 | p30 | Definition 3.18 (Small Factors). Define Rfac ∋ (N, ℓ; u, v) such that N = u·v and u, v∈ ±
1300 | p31 | Definition 3.19 (Damg ˚ ard-Fujisaki Params.). Define Rdf ∋ ( ˆN , t, s1, s2; λ1, λ2) such
1302 | p31 | Definition 3.20 (Damg ˚ ard-Fujisaki-star Params.). Define Rdf ∗ ∋ ( ˆN , t, s1, s2, d; λ1
1304 | p31 | Definition 3.21 (Discrete Log). Define Rdlog ∋ (G, g, q, X; w) such that gw = X ∈ G.
1305 | p31 | Definition 3.22 (Encrypted Discrete Log) . Define Rdlenc ∋ (G, g, q, N,C, ρ, nx, nλ, X, ℓ;
1314 | p31 | Definition 3.23 (Well-Formed Signature). Define Rsig ∋ (N, ρ,E, S, na, nb; a, b, η, µ) for
1319 | p31 | 3.6 The EC-Generic Group Model
1370 | p32 | 4.1 Sampling the RSA modulus
1392 | p33 | Algorithm SampleDF(1ℓ)
1417 | p33 | Algorithm 3: Algorithm for sampling a tough RSA modulus N and Damg ˚ ard-Fujisaki paramete
1418 | p33 | 4.2 Non-Interactive Setup
1426 | p34 | Algorithm Generate Auxiliary Signing Material
1459 | p34 | Algorithm 4: Non-interactive setup protocol executed ahead-of-time by the server
1460 | p34 | 4.3 Interactive Key-Generation
1478 | p35 | Protocol Generate Address – i.e. PK
1507 | p35 | Protocol 2: Interactive key-generation protocol.
1510 | p36 | 4.4 Distributed Signing
1513 | p36 | Protocol Signing
1539 | p36 | Protocol 3: Threshold signing protocol.
1540 | p36 | 5 Underlying ZK Protocols
1554 | p37 | Definition 5.1. Let R = {(X; w)} denote an NP-relation and let ℓ denote the security param
1604 | p38 | 5.1 Small Factors Proof ( Πfac)
1605 | p38 | Protocol Small Factors
1631 | p38 | Protocol 4: Small factor proof Π fac.
1641 | p39 | 5.1.1 Special Soundness of Πfac
1642 | p39 | Lemma 5.6 (Special Soundness). Using the notation above, let trans = ( eA, eB, eC, e, z1, 
1654 | p39 | 5.2 Well-Formed Modulus (Πmod)
1655 | p39 | Protocol Well-Formed Modulus
1676 | p40 | Protocol 5: Well-Formed Modulus Πmod.
1690 | p40 | Lemma 5.8. Using the notation from ‌Protocol 5, the following hold true.
1727 | p41 | 5.3 Well-Formed Signature ( Πsig)
1728 | p41 | Protocol Well-Formed Signature
1762 | p41 | Protocol 6: Well-Formed Signature Proof Πsig.
1765 | p41 | 5.3.1 Special Soundness of Πsig
1766 | p41 | Lemma 5.10 (Special Soundness). Using the notation above, let trans = ( ˜V ,˜B, D, e, z1, 
1789 | p42 | 5.3.2 Partial Straight-Line Extractability of Πsig in the GGM
1827 | p43 | 5.4 Discrete Logarithm ( Πdlog)
1828 | p43 | Protocol 5.13 (Discrete Logarithm).
1870 | p44 | 5.5 Encrypted Discrete Log ( Πdlenc)
1871 | p44 | Protocol Encrypted Discrete Log
1902 | p45 | Protocol 7: Encrypted Discrete Log Proof Π dlenc.
1933 | p46 | 5.6 Damg ˚ ard-Fujisaki Parameters (Πdf)
1934 | p46 | Protocol Damg ˚ ard-Fujisaki Params Proof
1943 | p46 | Protocol 8: Σ-protocol for proving correctness of the Damg ˚ ard-Fujisaki parameters (s1, 
1972 | p47 | 5.7 Damg ˚ ard-Fujisaki-star Parameters (Πdf∗)
1974 | p47 | Protocol Damg ˚ ard-Fujisaki-star Params Proof
1984 | p47 | Protocol 9: Σ-protocol for proving relaxed correctness of the Damg ˚ ard-Fujisaki paramete
1989 | p47 | 6 Security Analysis
1993 | p48 | Theorem 6.1. Assume the doubly-enhanced unforgeability of ECDSA, the SEDCR assumption, and
2003 | p48 | 6.1 Lazy symbolic interfacing with the GGM and the signing oracle
2049 | p49 | 6.1.1 Unique representations
2057 | p49 | Lemma 6.2 (Unique representations) . Let Q denote a bound on the total number of queries t
2075 | p50 | 6.1.2 Knowledge of exponents
2082 | p50 | Lemma 6.3. Let G be a generic group, and let µ : G → G be the associated bijective mapping
2087 | p50 | Lemma 6.3 is a classical result and has been proven in several works [Den06; AF07] in the 
2094 | p50 | 6.2 The client is corrupted, single key-generation
2104 | p51 | Theorem 6.4. Let A denote an adversary corrupting C, making at most QRO queries to the
2200 | p53 | Lemma 6.5. Assume that there exists a non-negligible δ such that
2342 | p57 | 6.3 The client is corrupted, multiple key-generation
2405 | p58 | 6.4 The server is corrupted
2414 | p58 | Theorem 6.8. Let A denote an adversary corrupting S, making at most QRO queries to the ran
2480 | p60 | Lemma 6.9. There exists algorithms FB, FC with running time comparable to that of A such t
2607 | p63 | 7 Unforgeability in the Generic Group Model
2665 | p64 | Definition 7.3. Using the notation above, we say that A breaks the unforgeability of Exper
2669 | p64 | Theorem 7.4. If Experiment 7.2 is unforgeable then Experiment 7.1 is unforgeable in the RO
2671 | p64 | 7.1 The Generic Group Model
2691 | p65 | Figure 1: Pictorial representation of the different algorithms/oracles in the GGM. The red
2693 | p65 | 7.1.1 Symbolic lazy evaluation
2742 | p66 | Theorem 7.5. Assume that A breaks the unforgeability of Experiment 7.2 in the GGM with pro
2746 | p66 | 7.2 Doubly-Enhanced Unforgeability in the GGM
2751 | p66 | Theorem 7.6. Let t denote an upper bound on the number of group and signing-oracle queries
2763 | p67 | 7.2.1 Preliminary F acts
2764 | p67 | Definition 7.7. For D = {(α, β, γ, ζ, m, r, e) ∈ F7q s.t. αζ ̸= eβ}, define ssig : D → Fq 
2780 | p67 | Lemma 7.9. For the identifying labels G of an eliptic curve encoded by the tuple (G, g, q)
2788 | p67 | 7.2.2 Simulation
2815 | p68 | Lemma 7.9 on input α−1eβ. If Z is not well defined or Z ∈ range(π), go to
2869 | p69 | 7.2.3 Analysis
3115 | p73 | 8 Benchmarks
3116 | p73 | 8.1 Concrete Parameters
3157 | p75 | 8.2 Experimental Benchmarks
3162 | p75 | Protocol Operation Average Min. Max. 10th perc. 99th perc. band.
3173 | p75 | Protocol Operation Average Min. Max. 10th perc. 99th perc. band.
3927 | p93 | Protocol 10: ‘Verifiable OLE’ from Single-Call Standard OLE in the ROM
