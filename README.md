# ML-KEM-768 Decapsulation Timing Assessment

Does decapsulation wall-clock timing reveal implicit rejection
(FIPS 203 §6.3, Algorithm 18)? Measured with a runnable harness
across four implementations: 2,400,000 decapsulations, 5 fresh
keypairs per implementation, 6 input classes, 20 batches of 1000
decapsulations each.

## Headline results

- **No timing difference between valid and implicitly-rejected
  decapsulations in any implementation.** Largest adversarial median
  difference: +0.400% (Kyber reference, SYNTH-RAND, neither test
  significant). Per implementation: pyca 0.124%, liboqs 0.110%,
  Go 0.220%, kyber-ref 0.400%. No pair met the rerun rule, so no
  confirmation reruns were performed.
- **The noise floor is the finding for Go.** Go's own VALID-vs-VALID
  null control differs by +1.155% (Mann-Whitney p = 0.0019) — larger
  than every Go adversarial effect. Go's ~1% drift over the run means
  sub-1% effects are undetectable for Go in this environment.
- **One discordant test pair (liboqs WRONGKEY):** Welch's t-test
  flags it (p = 0.0006) while the median difference is +0.017% and
  Mann-Whitney does not flag it (p = 0.2418) — a mean/outlier effect
  from a few slow batches, not a distributional shift.
- **FIPS 203 does not mandate constant-time execution** (the words
  "constant time" and "timing" do not appear in the standard); it
  requires the rejection flag to be destroyed, not returned (§3.3,
  §6.3). A null wall-clock result is therefore not a constant-time
  certification — and nothing here demonstrates exploitability
  either.
- **Absolute speeds (VALID median):** liboqs 22.953 µs, pyca
  52.187 µs, Go 129.482 µs, Kyber reference 133.157 µs.

## Implementations

| ID | Implementation | Version |
|---|---|---|
| A | pyca/cryptography (`cryptography.hazmat.primitives.asymmetric.mlkem`) | 50.0.2 |
| B | liboqs (`ML-KEM-768`, built from source; AVX2 path on this CPU) | 0.12.0, commit `f4b9622` |
| C | Go stdlib `crypto/mlkem` | go1.24.6 |
| D | pq-crystals/kyber Kyber768 reference (round-3, pre-FIPS 203 — lineage reference only) | commit `3edd5af` |

## Files

- `rubric.md` — the question, the FIPS 203 requirements, input classes, and the measurement protocol.
- `matrix.md` — per-class statistics and pairwise tests (Welch, Mann-Whitney, 95% CI, Cohen's d).
- `findings.md` — severity-ranked findings (F-1…F-6).
- `index.md` — claim-to-evidence index (M-1…M-16).
- `src/run_timing.py` — the harness (stdlib + `cryptography` + `ctypes`).
- `src/go-mlkem/main.go` — Go stdlib driver.
- `src/kyber-ref-driver.c` — Kyber reference driver.
- `outputs/timing-results.json` — one record per batch (2400).
- `outputs/timing-results.txt` — summary.
- `outputs/run_timing-2026-11-07-fresh.log` — unedited harness stdout (fresh full run).
- `outputs/run_timing.log` — unedited stdout of the earlier partial run (killed during kyber-ref keypair 1/5; identical copy `run_timing-2026-11-06-partial.log`).
- `outputs/SHA256SUMS` — digests of all outputs.
- `outputs/raw/fips-203.pdf` (+ `.txt`) — FIPS 203 primary source.
- `outputs/raw/SOURCES.txt` — source commit identifiers.

## Reproduce

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
`DONE`.

## Notes

- The Kyber reference implements round-3 Kyber768, not FIPS 203
  ML-KEM: its shared secrets are not comparable with A/B/C. Only its
  timing behavior is compared.
- The measured liboqs path is the pqcrystals-kyber-standard AVX2
  implementation, not the reference C code whose `verify`/`cmov`
  structure is discussed in `findings.md` F-6.
- Batch means are the unit of analysis: every statistic and test is
  computed over n=100 batch means per implementation per class, not
  over individual decapsulations.
