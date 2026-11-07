# Timing matrix — ML-KEM-768 decapsulation timing

Run: 2026-11-07T15:11:25Z–15:14:52Z (2026-11-07 22:11:25–22:14:52 WIB).
Harness: `src/run_timing.py`. Full machine-readable results:
`outputs/timing-results.json` (2400 batch records, 2,400,000
decapsulations). Unedited log:
`outputs/run_timing-2026-11-07-fresh.log`. Digests:
`outputs/SHA256SUMS`.

Design: 5 fresh keypairs per implementation; per keypair, 6 input
classes × 20 batches × 1000 decapsulations; batch order shuffled per
round; 200 warm-up decaps per keypair (discarded). All times are
**microseconds per decapsulation** (batch means). n=100 batch means
per implementation per class.

Reading the tests table: `med.diff` is the adversarial-class median
minus the VALID median; `med.diff %` is that as a percentage of the
VALID median. `Welch p` / `MWU p` are two-sided p-values (large-sample
normal approximations). `d` is Cohen's d. `CI95` is the 95%
confidence interval for the mean difference (VALID − adversarial).
"Suspicious" (rerun rule) = |median difference| > 0.5% of the VALID
median AND p < 0.01 on either test. **No pair was suspicious; no
reruns were performed.**

## A — pyca/cryptography 50.0.2 (VALID median 52.187 µs)

| Class | n | Mean µs | Median µs | Stdev µs | p5 µs | p25 µs | p75 µs | p95 µs | p99 µs |
|---|---|---|---|---|---|---|---|---|---|
| VALID | 100 | 53.319 | 52.187 | 3.393 | 51.800 | 51.973 | 52.802 | 62.487 | 68.258 |
| FLIP1 | 100 | 53.806 | 52.230 | 5.156 | 51.795 | 51.959 | 53.109 | 62.420 | 78.347 |
| FLIPMID | 100 | 53.376 | 52.123 | 4.485 | 51.835 | 51.935 | 52.671 | 55.524 | 78.000 |
| WRONGKEY | 100 | 53.191 | 52.144 | 3.826 | 51.748 | 51.973 | 52.819 | 56.092 | 62.004 |
| SYNTH-ZERO | 100 | 53.275 | 52.149 | 5.464 | 51.834 | 51.991 | 52.580 | 56.028 | 62.368 |
| SYNTH-RAND | 100 | 53.525 | 52.165 | 4.058 | 51.777 | 51.981 | 53.169 | 58.528 | 72.944 |

| Comparison | Med.diff µs | Med.diff % | Welch p | MWU p | Cohen's d | 95% CI (mean diff) µs | Suspicious |
|---|---|---|---|---|---|---|---|
| VALID-vs-VALID (null control) | −0.142 | −0.273% | 0.5217 | 0.4649 | −0.128 | [−1.770, +0.898] | — |
| VALID-vs-FLIP1 | +0.042 | +0.081% | 0.4303 | 0.7305 | −0.112 | [−1.697, +0.723] | No |
| VALID-vs-FLIPMID | −0.065 | −0.124% | 0.9194 | 0.5300 | −0.014 | [−1.159, +1.045] | No |
| VALID-vs-WRONGKEY | −0.043 | −0.082% | 0.8036 | 0.9786 | +0.035 | [−0.875, +1.130] | No |
| VALID-vs-SYNTH-ZERO | −0.038 | −0.073% | 0.9457 | 0.8317 | +0.010 | [−1.217, +1.304] | No |
| VALID-vs-SYNTH-RAND | −0.022 | −0.043% | 0.6967 | 0.8489 | −0.055 | [−1.243, +0.831] | No |

Largest adversarial median difference: 0.124% (FLIPMID). No test
significant at p < 0.01 on either test.

## B — liboqs 0.12.0, AVX2 path (VALID median 22.953 µs)

| Class | n | Mean µs | Median µs | Stdev µs | p5 µs | p25 µs | p75 µs | p95 µs | p99 µs |
|---|---|---|---|---|---|---|---|---|---|
| VALID | 100 | 23.021 | 22.953 | 0.239 | 22.779 | 22.880 | 23.080 | 23.582 | 23.834 |
| FLIP1 | 100 | 23.051 | 22.951 | 0.502 | 22.770 | 22.854 | 23.046 | 23.584 | 24.686 |
| FLIPMID | 100 | 23.199 | 22.955 | 2.235 | 22.769 | 22.863 | 23.047 | 23.410 | 23.804 |
| WRONGKEY | 100 | 23.215 | 22.957 | 0.509 | 22.801 | 22.856 | 23.362 | 24.276 | 24.430 |
| SYNTH-ZERO | 100 | 23.424 | 22.928 | 3.122 | 22.775 | 22.829 | 23.065 | 23.444 | 44.900 |
| SYNTH-RAND | 100 | 22.987 | 22.944 | 0.251 | 22.738 | 22.849 | 23.059 | 23.348 | 24.050 |

| Comparison | Med.diff µs | Med.diff % | Welch p | MWU p | Cohen's d | 95% CI (mean diff) µs | Suspicious |
|---|---|---|---|---|---|---|---|
| VALID-vs-VALID (null control) | −0.056 | −0.244% | 0.1279 | 0.1082 | −0.305 | [−0.166, +0.021] | — |
| VALID-vs-FLIP1 | −0.002 | −0.007% | 0.5960 | 0.5110 | −0.075 | [−0.139, +0.080] | No |
| VALID-vs-FLIPMID | +0.002 | +0.008% | 0.4306 | 0.4606 | −0.111 | [−0.618, +0.263] | No |
| VALID-vs-WRONGKEY | +0.004 | +0.017% | 0.0005939 | 0.2418 | −0.486 | [−0.304, −0.083] | No |
| VALID-vs-SYNTH-ZERO | −0.025 | −0.110% | 0.1991 | 0.1907 | −0.182 | [−1.016, +0.212] | No |
| VALID-vs-SYNTH-RAND | −0.008 | −0.036% | 0.3154 | 0.2181 | +0.142 | [−0.033, +0.103] | No |

Largest adversarial median difference: 0.110% (SYNTH-ZERO).
WRONGKEY is the one discordant pair in the whole study: Welch's
t-test flags it (p = 0.0006, mean higher by 0.194 µs) while the median
difference is +0.004 µs (+0.017%) and Mann-Whitney does not flag it
(p = 0.2418) — see findings.md F-2. Not suspicious under the rerun
rule (median criterion fails).

## C — Go 1.24.6 stdlib crypto/mlkem (VALID median 129.482 µs)

| Class | n | Mean µs | Median µs | Stdev µs | p5 µs | p25 µs | p75 µs | p95 µs | p99 µs |
|---|---|---|---|---|---|---|---|---|---|
| VALID | 100 | 130.401 | 129.482 | 4.064 | 128.141 | 128.517 | 130.868 | 135.513 | 136.585 |
| FLIP1 | 100 | 131.002 | 129.215 | 5.415 | 128.043 | 128.645 | 130.716 | 139.059 | 158.419 |
| FLIPMID | 100 | 130.526 | 129.365 | 3.974 | 128.008 | 128.582 | 131.100 | 135.653 | 147.923 |
| WRONGKEY | 100 | 130.466 | 129.359 | 4.151 | 128.058 | 128.651 | 130.566 | 133.580 | 152.334 |
| SYNTH-ZERO | 100 | 131.797 | 129.766 | 6.980 | 128.147 | 128.783 | 131.430 | 143.475 | 165.757 |
| SYNTH-RAND | 100 | 130.595 | 129.530 | 3.304 | 128.060 | 128.859 | 131.057 | 140.125 | 142.379 |

| Comparison | Med.diff µs | Med.diff % | Welch p | MWU p | Cohen's d | 95% CI (mean diff) µs | Suspicious |
|---|---|---|---|---|---|---|---|
| VALID-vs-VALID (null control) | **+1.496** | **+1.155%** | 0.01624 | **0.001921** | +0.481 | [+0.352, +3.464] | — |
| VALID-vs-FLIP1 | −0.267 | −0.206% | 0.3748 | 0.8202 | −0.126 | [−1.928, +0.726] | No |
| VALID-vs-FLIPMID | −0.117 | −0.090% | 0.8263 | 0.6477 | −0.031 | [−1.239, +0.989] | No |
| VALID-vs-WRONGKEY | −0.123 | −0.095% | 0.9112 | 0.9883 | −0.016 | [−1.203, +1.074] | No |
| VALID-vs-SYNTH-ZERO | +0.284 | +0.220% | 0.08387 | 0.09859 | −0.244 | [−2.979, +0.187] | No |
| VALID-vs-SYNTH-RAND | +0.048 | +0.037% | 0.7116 | 0.2747 | −0.052 | [−1.220, +0.833] | No |

Largest adversarial median difference: 0.220% (SYNTH-ZERO). The null
control itself exceeds every adversarial difference: the first half
of the VALID batches differs from the second half by +1.496 µs
(+1.155%, MWU p = 0.0019) — drift/noise, not a leak — see findings.md
F-1.

## D — pq-crystals/kyber Kyber768 reference (VALID median 133.157 µs)

| Class | n | Mean µs | Median µs | Stdev µs | p5 µs | p25 µs | p75 µs | p95 µs | p99 µs |
|---|---|---|---|---|---|---|---|---|---|
| VALID | 100 | 134.868 | 133.157 | 5.986 | 131.519 | 132.457 | 134.649 | 143.508 | 162.835 |
| FLIP1 | 100 | 134.677 | 133.225 | 5.197 | 131.714 | 132.434 | 134.897 | 140.259 | 164.155 |
| FLIPMID | 100 | 134.257 | 133.337 | 4.859 | 131.638 | 132.438 | 134.634 | 136.647 | 160.368 |
| WRONGKEY | 100 | 136.064 | 133.236 | 16.786 | 131.938 | 132.643 | 134.836 | 139.298 | 166.599 |
| SYNTH-ZERO | 100 | 134.534 | 133.222 | 5.184 | 131.717 | 132.493 | 134.511 | 137.754 | 161.157 |
| SYNTH-RAND | 100 | 134.951 | 133.690 | 5.390 | 131.665 | 132.728 | 135.004 | 144.078 | 162.277 |

| Comparison | Med.diff µs | Med.diff % | Welch p | MWU p | Cohen's d | 95% CI (mean diff) µs | Suspicious |
|---|---|---|---|---|---|---|---|
| VALID-vs-VALID (null control) | +0.226 | +0.170% | 0.4394 | 0.4607 | −0.155 | [−3.279, +1.424] | — |
| VALID-vs-FLIP1 | +0.069 | +0.051% | 0.8094 | 0.6285 | +0.034 | [−1.363, +1.745] | No |
| VALID-vs-FLIPMID | +0.181 | +0.136% | 0.4277 | 0.8393 | +0.112 | [−0.900, +2.123] | No |
| VALID-vs-WRONGKEY | +0.079 | +0.059% | 0.5023 | 0.3188 | −0.095 | [−4.689, +2.297] | No |
| VALID-vs-SYNTH-ZERO | +0.066 | +0.049% | 0.6733 | 0.8508 | +0.060 | [−1.218, +1.886] | No |
| VALID-vs-SYNTH-RAND | +0.533 | +0.400% | 0.9176 | 0.1011 | −0.015 | [−1.662, +1.496] | No |

Largest adversarial median difference: 0.400% (SYNTH-RAND), with
neither test significant. WRONGKEY's stdev (16.786 µs) is inflated by
one 296.597 µs outlier batch — scheduler noise, not a class effect
(median difference +0.059%).

## Cross-implementation speed (VALID median, µs per decapsulation)

| Implementation | VALID median µs | VALID mean µs |
|---|---|---|
| B liboqs 0.12.0 (AVX2) | 22.953 | 23.021 |
| A pyca/cryptography 50.0.2 | 52.187 | 53.319 |
| C Go 1.24.6 stdlib | 129.482 | 130.401 |
| D Kyber768 reference | 133.157 | 134.868 |

Absolute speed is a performance observation, not a security finding:
liboqs (AVX2) is ~5.6× faster than Go and ~2.3× faster than pyca on
this CPU (AMD EPYC 9D25, 4 vCPUs, load average 0.21–1.05 during the
run). Speed differences across implementations do not indicate a leak.

## Totals

- 2400 batches × 1000 reps = 2,400,000 decapsulations; 0 suspicious
  pairs; 0 reruns; 0 crashes; 0 errors.
- Largest adversarial median difference overall: +0.400%
  (kyber-ref SYNTH-RAND, neither test significant).
- Largest null-control median difference: +1.155% (Go) — the noise
  floor exceeds every adversarial effect measured.
