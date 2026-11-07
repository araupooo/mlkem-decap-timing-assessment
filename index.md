# Claim-to-evidence index — ML-KEM-768 decapsulation timing

Each claim cites the file and the exact location of its evidence.
`timing-results.json` holds one record per batch (2400 total, 100
batches per implementation per class, 1000 decapsulations each);
`run_timing-2026-11-07-fresh.log` is the unedited harness stdout;
`matrix.md` tabulates the per-class statistics and tests.

| Claim | Statement | Evidence |
|---|---|---|
| M-1 | The fresh run measured all 4 implementations × 5 fresh keypairs × 6 classes × 20 batches × 1000 reps = 2,400,000 decapsulations, exit 0. | `outputs/timing-results.json`, `total_batches: 2400`, `total_decaps: 2400000`; `outputs/run_timing-2026-11-07-fresh.log` tail (`TOTAL BATCHES: 2400`, `DONE`) |
| M-2 | pyca/cryptography 50.0.2: VALID median 52.187 µs; largest adversarial median difference 0.124% (FLIPMID, −0.065 µs); no test significant at p < 0.01. | `outputs/timing-results.json`, `stats` for `pyca-cryptography|*`, tests `pyca-cryptography VALID-vs-*`; `matrix.md` §A |
| M-3 | liboqs 0.12.0 (AVX2 path): VALID median 22.953 µs; largest adversarial median difference 0.110% (SYNTH-ZERO, −0.025 µs); no pair suspicious. | `outputs/timing-results.json`, `stats` for `liboqs|*`, tests `liboqs VALID-vs-*`; `matrix.md` §B |
| M-4 | Go 1.24.6 stdlib crypto/mlkem: VALID median 129.482 µs; largest adversarial median difference 0.220% (SYNTH-ZERO, +0.284 µs); no test significant at p < 0.01. | `outputs/timing-results.json`, `stats` for `go-stdlib-crypto-mlkem|*`, tests `go-stdlib-crypto-mlkem VALID-vs-*`; `matrix.md` §C |
| M-5 | Kyber768 reference: VALID median 133.157 µs; largest adversarial median difference 0.400% (SYNTH-RAND, +0.533 µs); neither test significant (Welch p = 0.9176, MWU p = 0.1011). | `outputs/timing-results.json`, `stats` for `kyber-ref|*`, tests `kyber-ref VALID-vs-*`; `matrix.md` §D |
| M-6 | No pair met the rerun rule (|median diff| > 0.5% AND p < 0.01); no confirmation reruns were performed. | `outputs/timing-results.json`, `"reruns": []`, every test `"suspicious": false`; `outputs/run_timing-2026-11-07-fresh.log`, `== confirmation reruns ==` section (empty) |
| M-7 | The Go null control (VALID-vs-VALID) differs by +1.496 µs (+1.155%), MWU p = 0.0019 — larger than every Go adversarial difference. The other null controls are small and non-significant (pyca −0.273%, liboqs −0.244%, kyber-ref +0.170%). | `outputs/timing-results.json`, tests with comparison `VALID-vs-VALID (null control)`; `findings.md` F-1 |
| M-8 | liboqs VALID-vs-WRONGKEY is discordant: Welch p = 0.0006 (mean +0.194 µs) but median difference +0.004 µs (+0.017%) and MWU p = 0.2418 — a mean/outlier effect, not a distributional shift. | `outputs/timing-results.json`, test `liboqs VALID-vs-WRONGKEY`; `findings.md` F-2 |
| M-9 | FIPS 203 §6.3 (Algorithm 18) defines implicit rejection and requires the step-9 rejection flag to be destroyed before Decaps_internal terminates and never returned in any form; §3.3 requires intermediate data to be destroyed. | `outputs/raw/fips-203.pdf`, §6.3 pp. 33–34, §3.3 p. 16; `outputs/raw/fips-203.txt` lines 1090–1092, 1913–1930, 1941–1952; `rubric.md` |
| M-10 | FIPS 203 does not explicitly mandate constant-time execution: the words "constant time" and "timing" do not appear in the standard. | Search of `outputs/raw/fips-203.txt` (zero hits); `findings.md` F-5 |
| M-11 | The Kyber reference compares ciphertexts with constant-time `verify()` and selects the secret with constant-time `cmov()`; `poly_frommsg` uses `cmov_int16`. | kyber-ref source `ref/verify.c` (doc comments), `ref/kem.c` lines 161–167, `ref/poly.c` `poly_frommsg`; `findings.md` F-6 |
| M-12 | The measured liboqs path is the pqcrystals-kyber-standard AVX2 implementation, not the reference C code (AVX2 enabled in the build, CPU has AVX2+BMI2+POPCNT). | liboqs `src/kem/ml_kem/kem_ml_kem_768.c` (AVX2 dispatch), `build/include/oqs/oqsconfig.h` (`OQS_ENABLE_KEM_ml_kem_768_avx2`, `OQS_DIST_BUILD`); `findings.md` F-4/F-6 |
| M-13 | The Kyber/ML-KEM reference lineage has had real timing leaks despite constant-time-looking source (Clangover, CVE-2024-37880; KyberSlash), so a null wall-clock result is not a constant-time certification. | PQShield disclosure, https://pqshield.com/pqshield-plugs-timing-leaks-in-kyber-ml-kem-to-improve-pqc-implementation-maturity/ ; `findings.md` F-5 |
| M-14 | The Go stdlib lineage's documented design uses constant-time field arithmetic and warns against `strcmp` for the implicit-rejection comparison — cited as design documentation, not as an independently verified property of the stdlib in this run. | https://words.filippo.io/mlkem768/ ; `findings.md` F-6 |
| M-15 | No crash, no error, no non-32-byte output in the fresh run; all 2400 batches completed. | `outputs/timing-results.json`, `total_batches: 2400`; `outputs/run_timing-2026-11-07-fresh.log`, exit 0, `DONE` |
| M-16 | The earlier partial run (2026-11-06, killed during kyber-ref keypair 1/5) is preserved unedited alongside the fresh run; it is not used for any result in this pack. | `outputs/run_timing.log` (= `outputs/run_timing-2026-11-06-partial.log`, identical SHA-256); `outputs/SHA256SUMS` |

## Primary sources

- FIPS 203, *Module-Lattice-Based Key-Encapsulation Mechanism Standard*,
  NIST, August 2024 — `outputs/raw/fips-203.pdf`
  (SHA-256 `fe1f12f32a7e44ec9fdebbf400cda843a40b506dee676725234dc6f7923b6cac`),
  plain text `outputs/raw/fips-203.txt`.
- liboqs 0.12.0 — `open-quantum-safe/liboqs`, commit
  `f4b96220e4bd208895172acc4fedb5a191d9f5b1` (built from source;
  the built library path is given by LIBOQS_SO in `src/run_timing.py`).
- pq-crystals/kyber — commit `3edd5af5991927164edd4aacebfcbee00b8064e7`
  (source in the sibling `src/kyber-ref`).
- pyca/cryptography 50.0.2 — `cryptography.hazmat.primitives.asymmetric.mlkem`.
- Go 1.24.6 stdlib — `crypto/mlkem`.
- PQShield, "PQShield plugs timing leaks in Kyber / ML-KEM" —
  https://pqshield.com/pqshield-plugs-timing-leaks-in-kyber-ml-kem-to-improve-pqc-implementation-maturity/
- Filippo Valsorda, "Post-quantum Cryptography for the Go Ecosystem" —
  https://words.filippo.io/mlkem768/

## Reproduction

```
python3 -m venv /tmp/mlkem-timing-venv
/tmp/mlkem-timing-venv/bin/pip install "cryptography==50.0.2"

# liboqs 0.12.0 (built library expected at the path in src/run_timing.py,
# LIBOQS_SO — set the LIBOQS_SO environment variable, or edit the default in
# src/run_timing.py to point at your local liboqs build):
cmake -S src/liboqs -B src/liboqs/build -DBUILD_SHARED_LIBS=ON -DCMAKE_BUILD_TYPE=Release
cmake --build src/liboqs/build -j"$(nproc)"

# Go driver (needs go1.24.6):
(cd src/go-mlkem && go build -o gomlkem .)

# Kyber reference driver (needs gcc):
cc -O2 -DKYBER_K=3 -Isrc/kyber-ref/ref src/kyber-ref/ref/{kem,indcpa,polyvec,poly,ntt,cbd,reduce,verify,fips202,symmetric-shake,randombytes}.c \
   src/kyber-ref-driver.c -o src/kyber768-driver

/tmp/mlkem-timing-venv/bin/python src/run_timing.py > outputs/run_timing-2026-11-07-fresh.log
```

Expected: exit 0, `TOTAL BATCHES: 2400`, `TOTAL DECAPS: 2400000`,
`DONE`. The harness writes `outputs/timing-results.json` and
`outputs/timing-results.txt` directly.
