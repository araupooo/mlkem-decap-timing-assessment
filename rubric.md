# Rubric — ML-KEM-768 decapsulation timing assessment

Source of expected behavior: FIPS 203, *Module-Lattice-Based
Key-Encapsulation Mechanism Standard* (NIST.FIPS.203, August 2024),
file `outputs/raw/fips-203.pdf` (SHA-256
`fe1f12f32a7e44ec9fdebbf400cda843a40b506dee676725234dc6f7923b6cac`),
plain text `outputs/raw/fips-203.txt`.

Parameter set under test: ML-KEM-768 (Table 2: n=256, q=3329, k=3,
η1=2, η2=2, du=10, dv=4). Table 3 sizes: encapsulation key 1184 bytes,
decapsulation key 2400 bytes, ciphertext 1088 bytes, shared secret
32 bytes.

## The question

Does decapsulation wall-clock timing reveal implicit rejection
(FIPS 203 §6.3, Algorithm 18) — i.e. can an observer distinguish a
valid ciphertext (accepted) from an adversarial one (implicitly
rejected) by timing alone?

## What FIPS 203 actually requires

### §6.3, Algorithm 18 — ML-KEM.Decaps_internal(dk, c)

Decapsulation decrypts `c` to `m'`, re-encrypts `m'` with derived
randomness `r'`, and compares the re-encrypted ciphertext `c'` with
the provided `c`. If `c ≠ c'`, the algorithm performs **implicit
rejection**: `K' ← J(z‖c)` — a 32-byte shared secret derived from the
rejection value `z` stored in the decapsulation key and the provided
ciphertext. In either case decapsulation outputs a 32-byte shared
secret; no error is raised.

> "The 'implicit reject' flag computed in step 9 (by comparing c and
> c′) is a secret piece of intermediate data. As specified in the
> requirements in Section 3.3, this flag shall be destroyed prior to
> ML-KEM.Decaps_internal terminating. In particular, returning the
> value of the flag as an output in any form is not permitted."
> (FIPS 203 §6.3)

### §3.3 — Destruction of intermediate values

> "Implementers shall ensure that intermediate data is destroyed as
> soon as it is no longer needed. In particular, for ML-KEM.KeyGen,
> ML-KEM.Encaps, and ML-KEM.Decaps, only the designated output can be
> retained in memory after the algorithm terminates. All other data
> shall be destroyed prior to the algorithm terminating."
> (FIPS 203 §3.3)

### What FIPS 203 does NOT require

The words "constant time" and "timing" do not appear anywhere in
FIPS 203 (verified by searching the local `fips-203.txt`). The
standard requires the rejection flag to be **destroyed, not
returned** — it does not explicitly mandate constant-time execution.
A timing difference, if one existed, would therefore be an
implementation property to measure, not a direct standard violation;
and the absence of a measurable wall-clock difference does not prove
an implementation is constant-time at finer granularity (see
`findings.md` F-5).

## Input classes

| Class | Input | Expected behavior |
|---|---|---|
| VALID | valid encapsulation under the tested key | accepted; decapsulated secret equals the encapsulation secret |
| FLIP1 | valid ciphertext with one bit flipped (ct[0]) | implicit rejection (§6.3): 32-byte secret ≠ valid secret, no error |
| FLIPMID | valid ciphertext with one bit flipped (ct[543]) | implicit rejection (§6.3) |
| WRONGKEY | valid ciphertext decapsulated with a different keypair | implicit rejection (§6.3) |
| SYNTH-ZERO | all-zero 1088-byte ciphertext | implicit rejection (§6.3) |
| SYNTH-RAND | random 1088-byte ciphertext | implicit rejection (§6.3) |

The two flip positions (ct[0] and ct[543]) probe different parts of
the ciphertext (first byte vs middle); SYNTH-ZERO and SYNTH-RAND
probe ciphertexts with no valid structure at all. All five
adversarial classes must follow the same code path as VALID through
decrypt → re-encrypt → compare → select, differing only in the
comparison outcome (step 9) and the selected secret (step 10).

## Measurement protocol

- **Implementations:** A pyca/cryptography 50.0.2, B liboqs 0.12.0
  (built from source; AVX2 path on this CPU — see below), C Go 1.24.6
  stdlib `crypto/mlkem`, D pq-crystals/kyber Kyber768 reference
  (round-3, pre-FIPS 203 — lineage reference only).
- **Per implementation:** 5 fresh keypairs. Per keypair: 6 input
  classes, each measured as B=20 batches of R=1000 decapsulations.
  The timed region is pure decapsulation (key parsed once per keypair,
  outside the loop). For C and D the batch loop runs inside the driver
  process (`timedecap`), so stdin/stdout pipe overhead is excluded;
  for A and B the batch loop runs in-process. Every implementation is
  measured the same way (batch means), so the numbers are comparable.
- **Interleaving:** batch order across the 6 classes is shuffled per
  round to defeat drift; 200 warm-up decaps per keypair (discarded).
- **Statistics per class:** n (batch means), mean, median, stdev,
  p5/p25/p75/p95/p99 (microseconds).
- **Pairwise VALID vs each adversarial class:** Welch's t-test
  (unequal variances) and Mann-Whitney U, both with large-sample
  normal approximations, 95% CI for the mean difference, Cohen's d.
- **Null control:** the VALID batches are split in half and tested
  VALID-vs-VALID (false-positive / noise-floor calibration). A
  "significant" result here measures drift and the noise floor of the
  procedure, not a leak.
- **Rerun rule:** any pair with |median difference| > 0.5% of the
  VALID median AND p < 0.01 on either test is re-run once with a fresh
  keypair and fresh random order; the rerun is reported alongside
  (confirm/refute). No pair met this rule in this run, so no reruns
  were performed (`"reruns": []` in `outputs/timing-results.json`).

## Interpretation rules (fixed before the run)

- A timing difference is **evidence of a leak only if** it exceeds
  the null-control noise floor in magnitude, is significant on both
  the mean-based (Welch) and rank-based (Mann-Whitney) tests, and
  confirms on rerun.
- A mean-based test alone flagging a pair while the median difference
  is negligible and the rank test is not significant indicates
  outlier sensitivity (a few slow batches), not a distributional
  shift — see `findings.md` F-2.
- A measured timing difference is **not** proven exploitability: an
  attacker would still need to turn a batch-mean difference into a
  per-decapsulation distinguisher under realistic noise. Conversely,
  no measurable difference at this granularity does not prove
  constant-time execution (see `findings.md` F-5).

## Implementations under test

| ID | Implementation | Version / source | Key encoding | Measured code path |
|---|---|---|---|---|
| A | pyca/cryptography | 50.0.2 (`cryptography.hazmat.primitives.asymmetric.mlkem`) | ek 1184 B; dk as 64-byte seed (d‖z) | OpenSSL ML-KEM backend (constant-time status not verified from a primary source in this run — see findings.md F-6) |
| B | liboqs | 0.12.0, built from source (`open-quantum-safe/liboqs`, commit `f4b96220e4bd208895172acc4fedb5a191d9f5b1`) | ek 1184 B; sk 2400 B expanded | pqcrystals-kyber-standard AVX2 (`OQS_ENABLE_KEM_ml_kem_768_avx2`, `OQS_DIST_BUILD`, CPU has AVX2+BMI2+POPCNT) — the AVX2 path, not the reference C code |
| C | Go stdlib crypto/mlkem | go1.24.6, stdlib `crypto/mlkem` | ek 1184 B; dk as 64-byte seed (d‖z) | Go stdlib (constant-time status not independently verified in this run — see findings.md F-6) |
| D | pq-crystals/kyber Kyber768 reference | commit `3edd5af5991927164edd4aacebfcbee00b8064e7` | pk 1184 B; sk 2400 B | reference C code (`kem.c` + `verify.c`), compiled gcc -O2 |

D is a **lineage reference only**: it implements round-3 Kyber768
(pre-FIPS 203). Its KEM hashing differs from FIPS 203, so its shared
secrets are not comparable with A/B/C and it is excluded from any
cross-implementation agreement check. Only its *timing behavior* is
compared.

## Harness

`src/run_timing.py` (stdlib + `cryptography` + the `ctypes` liboqs
binding; Go and Kyber drivers are small subprocess programs in
`src/go-mlkem/main.go` and `src/kyber-ref-driver.c`). The harness
writes `outputs/timing-results.json` (one record per batch, 2400),
`outputs/timing-results.txt` (summary), and its stdout is preserved
unedited in `outputs/run_timing-2026-11-07-fresh.log`. An earlier
partial run (killed during the Kyber reference keypair 1/5) is
preserved unedited as `outputs/run_timing.log` (identical copy:
`outputs/run_timing-2026-11-06-partial.log`).
