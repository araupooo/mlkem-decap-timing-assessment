# Findings — ML-KEM-768 decapsulation timing

Ordered by severity. Every finding cites the measured batches in
`outputs/timing-results.json` and the unedited log
`outputs/run_timing-2026-11-07-fresh.log`. All times are microseconds
per decapsulation (batch means, n=100 per implementation per class).

## F-1 — Informational (method): the Go null control drifts more than any adversarial effect — the noise floor, not a leak

**Observation.** For Go 1.24.6 stdlib `crypto/mlkem`, the VALID-vs-VALID
null control — the first 50 VALID batches tested against the last 50 —
differs by +1.496 µs (+1.155% of the VALID median 129.482 µs), with
Mann-Whitney p = 0.0019 and Welch p = 0.0162 (Cohen's d = +0.481).
Every adversarial comparison for Go is smaller than this: the largest
is SYNTH-ZERO at +0.284 µs (+0.220%, Welch p = 0.0839, MWU
p = 0.0986), and the rest are within ±0.21%.

**Why it matters.** The null control calibrates the false-positive
rate of the procedure: two halves of the *same* class, measured under
the same protocol, produce a "significant" difference. The Go
measurements therefore drift by ~1% over the course of the run
(likely scheduler/GC/thermal drift on a shared 4-vCPU VM; batch order
was shuffled per round, but the split-half still separates early from
late batches). Any real VALID-vs-adversarial effect below ~1% is
undetectable for Go in this setup — and none was found above that
either. The correct reading is not "Go leaks" (the null control is
VALID-vs-VALID, so it cannot be a leak) but "Go's noise floor in this
environment is ~1.2%, and all adversarial effects sit well below
it."

**Scope and mitigation.** This is a limitation of the measurement
environment, not of the implementation. A future run that needs
sub-1% sensitivity for Go would need a quieter machine, per-keypair
paired comparisons, or a longer run with the null control computed
per keypair. The other three implementations' null controls are small
(pyca −0.273%, liboqs −0.244%, kyber-ref +0.170%, none significant),
so their sub-0.5% bounds stand as measured.

**Evidence:** `outputs/timing-results.json`, tests with comparison
`VALID-vs-VALID (null control)` for `go-stdlib-crypto-mlkem`;
`matrix.md` §C.

## F-2 — Informational: one discordant test pair (liboqs WRONGKEY) shows why the protocol requires median + rank agreement

**Observation.** For liboqs 0.12.0, VALID-vs-WRONGKEY: Welch's t-test
flags the pair (t = −3.434, p = 0.0006; mean higher by 0.194 µs,
95% CI [−0.304, −0.083] µs for VALID − WRONGKEY), yet the median
difference is +0.004 µs (+0.017% of the VALID median 22.953 µs) and
Mann-Whitney does not flag it (U = 4521, p = 0.2418). The mean shift
is driven by a few slow batches (WRONGKEY stdev 0.509 µs vs VALID
0.239 µs; FLIPMID and SYNTH-ZERO show the same pattern with single
batches up to 45.261 µs and 45.330 µs against a ~23 µs baseline).

**Why it matters.** A mean-based test on batch means is sensitive to
rare slow batches (scheduler preemption on a shared VM). The
protocol's rerun rule therefore requires *both* a median difference
above 0.5% *and* p < 0.01; this pair fails the median criterion by a
factor of ~30, so it is not suspicious and no rerun was triggered.
Reporting the Welch p-value alone would have been a false alarm.

**Evidence:** `outputs/timing-results.json`, test
`liboqs / VALID-vs-WRONGKEY`; `matrix.md` §B. The same
outlier-batch pattern (isolated batches 2× the baseline) appears in
kyber-ref WRONGKEY (one 296.597 µs batch, stdev 16.786 µs, median
difference +0.059%).

## F-3 — Positive: no timing difference between valid and implicitly-rejected decapsulations in any implementation

**Observation.** Across all four implementations and all five
adversarial classes (20 pairs), the largest median difference is
+0.400% (kyber-ref SYNTH-RAND, Welch p = 0.9176, MWU p = 0.1011),
and no pair is significant at p < 0.01 on either test except the
discordant liboqs WRONGKEY pair discussed in F-2 (median +0.017%).
Per implementation, the largest adversarial median differences are:
pyca 0.124% (FLIPMID), liboqs 0.110% (SYNTH-ZERO), Go 0.220%
(SYNTH-ZERO), kyber-ref 0.400% (SYNTH-RAND). No pair met the rerun
rule, so no confirmation reruns were performed.

**Why it matters.** The implicit-rejection flag (FIPS 203 §6.3,
Algorithm 18 step 9) is a secret intermediate value that must be
destroyed before decapsulation terminates (§3.3) and must not be
returned in any form. This measurement tests whether the flag leaks
*through wall-clock timing*: in 2,400,000 decapsulations it does not,
at the sensitivity of this setup (median differences ≤0.40%,
bounded by the null-control noise floors: pyca 0.273%, liboqs 0.244%,
Go 1.155%, kyber-ref 0.170%).

**Scope.** This is a wall-clock, batch-mean result on one VM. It does
not prove constant-time execution at finer granularity (see F-5).

**Evidence:** `outputs/timing-results.json`, all 20 VALID-vs-
adversarial tests (`"suspicious": false`); `matrix.md` §§A–D.

## F-4 — Informational: absolute speeds differ widely; liboqs (AVX2) is fastest

**Observation.** VALID medians: liboqs 22.953 µs, pyca 52.187 µs,
Go 129.482 µs, kyber-ref 133.157 µs (AMD EPYC 9D25, 4 vCPUs).
liboqs is ~5.6× faster than Go and ~2.3× faster than pyca on this
CPU. The measured liboqs path is the pqcrystals-kyber-standard AVX2
implementation (`OQS_ENABLE_KEM_ml_kem_768_avx2`, dist build, CPU has
AVX2+BMI2+POPCNT) — not the reference C code.

**Why it matters.** Speed is a performance observation, not a
security finding: the fastest implementation (liboqs) also shows the
smallest median differences. But the AVX2 path matters for the
source-level claims in F-6: the constant-time `verify`/`cmov`
structure verified in the reference C code is not the code that
actually ran for liboqs.

**Evidence:** `outputs/timing-results.json`, `stats` for
`|VALID` classes; liboqs build config
(`src/liboqs/build/include/oqs/oqsconfig.h`,
`OQS_ENABLE_KEM_ml_kem_768_avx2`).

## F-5 — Caveat: a null wall-clock result is not proof of constant-time execution, and not proof of exploitability either

**Observation.** Two directions, both verified against primary
sources:

1. FIPS 203 does not mandate constant-time execution: the words
   "constant time" and "timing" do not appear anywhere in the local
   `fips-203.txt`. The standard requires the rejection flag to be
   destroyed, not returned (§3.3, §6.3) — a requirement about the
   value, not about execution time.
2. The Kyber/ML-KEM reference lineage has had real timing leaks
   despite constant-time-looking source: PQShield's disclosure
   (pqshield.com) documents that `poly_frommsg` in the reference
   implementation — the same function present in the kyber-ref source
   used here (`ref/poly.c`, via `cmov_int16`) — was compiled by Clang
   into a secret-dependent branch (Clangover, CVE-2024-37880), and
   that secret-dependent division in decapsulation enabled key
   recovery on demonstrated hardware (KyberSlash). A wall-clock
   batch-mean study like this one cannot see a single-branch leak of
   that kind, and cannot rule out finer-grained leakage (cache,
   branch predictor, per-operation timing).

**Why it matters.** The honest statement of F-3 is narrow: *at
batch-mean wall-clock granularity, on this machine, valid and
rejected decapsulations are indistinguishable*. It is not a
constant-time certification, and the absence of a measurable
difference here must not be cited as one. Conversely, nothing in
this run demonstrates exploitability either: no measured difference
is large enough, consistent enough, or confirmed on rerun to serve
as a distinguisher.

**Evidence:** FIPS 203 text search (zero hits for "constant time" /
"timing"); `ref/poly.c` `poly_frommsg` in the kyber-ref source;
PQShield, "PQShield plugs timing leaks in Kyber / ML-KEM"
(https://pqshield.com/pqshield-plugs-timing-leaks-in-kyber-ml-kem-to-improve-pqc-implementation-maturity/).

## F-6 — Informational: what was — and was not — verified about constant-time structure

**Verified in source (this run):**

- **Kyber reference (D):** `ref/kem.c` compares the re-encrypted
  ciphertext with the provided ciphertext using `verify()` —
  documented in `ref/verify.c` as "Compare two arrays for equality
  in constant time" — and selects the returned secret with `cmov()`,
  documented as "Runs in constant time" (`kem.c` lines 161–167).
  `poly_frommsg` uses `cmov_int16` per message bit (`ref/poly.c`).
- **liboqs reference code:** the same `verify.c`/`cmov` structure
  exists in liboqs's bundled
  `pqcrystals-kyber-standard_ml-kem-768_ref/` source. However, the
  binary actually measured uses the AVX2 path (F-4), whose
  constant-time structure was **not** source-verified in this run.
- **Go stdlib lineage:** Filippo Valsorda's write-up of the pure-Go
  ML-KEM-768 implementation documents constant-time arithmetic for
  its field operations (Barrett reduction) and notes that the
  implicit-rejection ciphertext comparison must not use `strcmp`
  (https://words.filippo.io/mlkem768/). The Go stdlib's own
  constant-time properties were **not** independently verified in
  this run.

**Not verified (stated as unverified, not as a claim):**

- pyca/cryptography 50.0.2 delegates ML-KEM to its OpenSSL backend;
  no constant-time guarantee for that backend was verified from a
  primary source in this run. The measurement (F-3) is the evidence
  for pyca, not a source claim.
- No dudect-style or cycle-accurate constant-time test was run for
  any implementation; the harness measures wall-clock batch means
  only.

**Evidence:** `ref/verify.c`, `ref/kem.c`, `ref/poly.c` in the
kyber-ref source; liboqs `src/kem/ml_kem/kem_ml_kem_768.c` (AVX2
dispatch) and `oqsconfig.h`; words.filippo.io/mlkem768.
