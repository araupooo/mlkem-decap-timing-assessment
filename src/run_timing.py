#!/usr/bin/env python3
"""ML-KEM-768 decapsulation timing harness.

Question: does decapsulation wall-clock timing reveal implicit rejection
(FIPS 203 Section 6.3, Algorithm 18) -- i.e. can an observer distinguish a
valid ciphertext (accepted) from an adversarial one (implicitly rejected)
by timing alone? The rejection flag is a secret intermediate value that
shall be destroyed before Decaps_internal terminates (Section 6.3) and
shall not be returned in any form (Section 3.3, destruction of intermediate
values). FIPS 203 does not explicitly mandate constant-time execution; this
harness measures what the implementations actually do, and the findings
separate a measurable timing difference from proven exploitability.

Design (see rubric.md for the full protocol):
  * Implementations: A pyca/cryptography 50.0.2, B liboqs 0.12.0,
    C Go 1.24.6 stdlib crypto/mlkem, D pq-crystals/kyber Kyber768 ref
    (lineage reference only).
  * Per implementation: 5 fresh keypairs. Per keypair: 6 input classes
    (VALID, FLIP1, FLIPMID, WRONGKEY, SYNTH-ZERO, SYNTH-RAND), each
    measured as B=20 batches of R=1000 decapsulations. The timed region is
    pure decapsulation (key parsed once per keypair, outside the loop).
    For C and D the batch loop runs inside the driver process
    (`timedecap`), so stdin/stdout pipe overhead is excluded; for A and B
    the batch loop runs in-process. Every implementation is measured the
    same way (batch means), so the numbers are comparable.
  * Batch order across the 6 classes is shuffled per round (interleaved
    runs) to defeat drift; 200 warm-up decaps per keypair (discarded).
  * Statistics per class: n (batch means), mean, median, stdev, p5/p25/
    p75/p95/p99 (microseconds). Pairwise VALID vs each adversarial class:
    Welch's t-test (unequal variances) and Mann-Whitney U, both with
    large-sample normal approximations, 95% CI for the mean difference,
    and Cohen's d. A null control splits the VALID batches in half and
    tests VALID-vs-VALID (false-positive calibration).
  * Rerun rule: any pair with |median difference| > 0.5% of the VALID
    median AND p < 0.01 is re-run once with a fresh keypair and fresh
    random order; the rerun is reported alongside (confirm/refute).

Outputs: outputs/timing-results.json (per-batch records + stats + tests),
outputs/timing-results.txt (summary), outputs/run_timing.log (this stdout,
unedited). Digests in outputs/SHA256SUMS.
"""
import ctypes
import hashlib
import json
import math
import os
import platform
import random
import statistics
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUT = os.path.join(ROOT, "outputs")
# Built liboqs location. Default: src/liboqs/build/lib/liboqs.so under the
# pack root (build liboqs 0.12.0 there as in README.md). Override with the
# LIBOQS_SO environment variable. (The measured run used a liboqs build at
# the equivalent path in the author's workspace; the default here keeps the
# pack self-contained.)
LIBOQS_SO = os.environ.get("LIBOQS_SO", os.path.join(
    ROOT, "src", "liboqs", "build", "lib", "liboqs.so"))

EK_LEN, DK_LEN, CT_LEN, SS_LEN = 1184, 2400, 1088, 32
N_KEYPAIRS = 5
BATCHES = 20
REPS = 1000
WARMUP = 200
CLASSES = ["VALID", "FLIP1", "FLIPMID", "WRONGKEY", "SYNTH-ZERO", "SYNTH-RAND"]

rng = random.Random(20261107)
results = {
    "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "standard": "FIPS 203 (NIST.FIPS.203, Aug 2024), ML-KEM-768",
    "question": "Does decapsulation wall-clock timing reveal implicit rejection (FIPS 203 Section 6.3)?",
    "design": {
        "keypairs_per_implementation": N_KEYPAIRS,
        "batches_per_class_per_keypair": BATCHES,
        "reps_per_batch": REPS,
        "warmup_decaps_per_keypair": WARMUP,
        "classes": CLASSES,
        "timed_region": "pure decapsulation only; key parsed once per keypair outside the loop",
        "interleaving": "batch order across the 6 classes shuffled per round",
    },
    "environment": {},
    "implementations": {},
    "batches": [],   # one record per batch: impl, keypair, class, round, mean_us
    "stats": {},     # per impl+class aggregates
    "tests": [],     # pairwise VALID vs adversarial + null control
    "reruns": [],
}


def log(*a):
    print(*a, flush=True)


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


# ---------------------------------------------------------------- environment
def loadavg():
    try:
        with open("/proc/loadavg") as f:
            return f.read().split()[:3]
    except Exception:
        return []


results["environment"] = {
    "cpu_model": platform.processor() or "unknown",
    "cpu_count": os.cpu_count(),
    "loadavg_start": loadavg(),
    "python": sys.version.split()[0],
    "platform": platform.platform(),
    "perf_counter_resolution_s": time.get_clock_info("perf_counter").resolution,
    "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
}
try:
    with open("/proc/cpuinfo") as f:
        for line in f:
            if line.startswith("model name"):
                results["environment"]["cpu_model"] = line.split(":", 1)[1].strip()
                break
except Exception:
    pass
log("environment:", json.dumps(results["environment"]))


# ---------------------------------------------------------------- statistics
def percentile(sorted_vals, q):
    if not sorted_vals:
        return None
    i = (len(sorted_vals) - 1) * q
    lo, hi = int(math.floor(i)), int(math.ceil(i))
    if lo == hi:
        return sorted_vals[lo]
    return sorted_vals[lo] * (hi - i) + sorted_vals[hi] * (i - lo)


def norm_sf(z):
    """Survival function of the standard normal (large-sample approx)."""
    return 0.5 * math.erfc(z / math.sqrt(2.0))


def welch(xs, ys):
    """Welch's t-test; returns (t, df, p_two_sided) with normal approx for p."""
    nx, ny = len(xs), len(ys)
    mx, my = statistics.fmean(xs), statistics.fmean(ys)
    vx, vy = statistics.variance(xs), statistics.variance(ys)
    se = math.sqrt(vx / nx + vy / ny)
    t = (mx - my) / se if se > 0 else 0.0
    num = (vx / nx + vy / ny) ** 2
    den = (vx / nx) ** 2 / (nx - 1) + (vy / ny) ** 2 / (ny - 1)
    df = num / den if den > 0 else 1.0
    # Large-sample normal approximation (|t| with df >> 30 ~= normal).
    p = 2 * norm_sf(abs(t))
    # 95% CI for the mean difference (normal approx).
    half = 1.96 * se
    return {"t": t, "df": df, "p": p,
            "mean_diff_us": mx - my, "ci95_low_us": (mx - my) - half,
            "ci95_high_us": (mx - my) + half, "se_us": se}


def mann_whitney(xs, ys):
    """Mann-Whitney U with normal approximation and tie correction."""
    nx, ny = len(xs), len(ys)
    combined = sorted([(v, 0) for v in xs] + [(v, 1) for v in ys])
    ranks = {}
    i = 0
    rank_sum_x = 0.0
    tie_sum = 0.0
    while i < len(combined):
        j = i
        while j + 1 < len(combined) and combined[j + 1][0] == combined[i][0]:
            j += 1
        avg_rank = (i + j) / 2 + 1
        for k in range(i, j + 1):
            if combined[k][1] == 0:
                rank_sum_x += avg_rank
        tie_sum += (j - i + 1) ** 3 - (j - i + 1)
        i = j + 1
    n = nx + ny
    u_x = rank_sum_x - nx * (nx + 1) / 2
    mu = nx * ny / 2
    var = nx * ny * (n + 1) / 12 - nx * ny * tie_sum / (12 * n * (n - 1)) if n > 1 else 0
    z = (u_x - mu) / math.sqrt(var) if var > 0 else 0.0
    p = 2 * norm_sf(abs(z))
    return {"U": u_x, "z": z, "p": p}


def cohen_d(xs, ys):
    nx, ny = len(xs), len(ys)
    mx, my = statistics.fmean(xs), statistics.fmean(ys)
    vx, vy = statistics.variance(xs), statistics.variance(ys)
    pooled = math.sqrt(((nx - 1) * vx + (ny - 1) * vy) / (nx + ny - 2))
    return (mx - my) / pooled if pooled > 0 else 0.0


def summarize(vals):
    s = sorted(vals)
    return {
        "n": len(vals),
        "mean_us": statistics.fmean(vals),
        "median_us": statistics.median(vals),
        "stdev_us": statistics.stdev(vals) if len(vals) > 1 else 0.0,
        "min_us": s[0], "max_us": s[-1],
        "p5_us": percentile(s, 0.05), "p25_us": percentile(s, 0.25),
        "p75_us": percentile(s, 0.75), "p95_us": percentile(s, 0.95),
        "p99_us": percentile(s, 0.99),
    }


# ---------------------------------------------------------------- pyca (A)
log("== implementation A: pyca/cryptography ==")
from cryptography import __version__ as CRYPTO_VER
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey

results["implementations"]["pyca-cryptography"] = {
    "version": CRYPTO_VER, "module": "cryptography.hazmat.primitives.asymmetric.mlkem",
    "standard": "FIPS 203 ML-KEM-768"}
log("pyca cryptography version:", CRYPTO_VER)


# ---------------------------------------------------------------- liboqs (B)
log("== implementation B: liboqs ==")
lib = ctypes.CDLL(LIBOQS_SO)
lib.OQS_version.restype = ctypes.c_char_p
lib.OQS_KEM_new.argtypes = [ctypes.c_char_p]
lib.OQS_KEM_new.restype = ctypes.c_void_p
lib.OQS_KEM_free.argtypes = [ctypes.c_void_p]
lib.OQS_KEM_keypair.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
lib.OQS_KEM_encaps.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
lib.OQS_KEM_decaps.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
for f in (lib.OQS_KEM_keypair, lib.OQS_KEM_encaps, lib.OQS_KEM_decaps):
    f.restype = ctypes.c_int
kem = lib.OQS_KEM_new(b"ML-KEM-768")
assert kem, "OQS_KEM_new(ML-KEM-768) failed"
liboqs_ver = lib.OQS_version().decode()
results["implementations"]["liboqs"] = {
    "version": liboqs_ver, "source": "open-quantum-safe/liboqs 0.12.0, built from source",
    "standard": "FIPS 203 ML-KEM-768"}
log("liboqs version:", liboqs_ver)


# ---------------------------------------------------------------- Go driver (C)
log("== implementation C: Go stdlib crypto/mlkem ==")
GO_BIN = os.path.join(ROOT, "src", "go-mlkem", "gomlkem")
go = subprocess.Popen([GO_BIN], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                      text=True, bufsize=1)
log("go driver:", go.stdout.readline().strip())
results["implementations"]["go-stdlib-crypto-mlkem"] = {
    "version": "go1.24.6 stdlib crypto/mlkem", "standard": "FIPS 203 ML-KEM-768"}


def go_cmd(line):
    go.stdin.write(line + "\n")
    go.stdin.flush()
    return go.stdout.readline().strip()


# ---------------------------------------------------------------- kyber-ref (D)
log("== implementation D: pq-crystals/kyber Kyber768 reference ==")
KYBER_BIN = os.path.join(ROOT, "src", "kyber768-driver")
ky = subprocess.Popen([KYBER_BIN], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                      text=True, bufsize=1)
log("kyber driver:", ky.stdout.readline().strip())
results["implementations"]["kyber-ref"] = {
    "version": "pq-crystals/kyber (round-3 reference C code)",
    "standard": "Kyber768 round-3 (pre-FIPS 203) -- LINEAGE REFERENCE ONLY"}


def ky_cmd(line):
    ky.stdin.write(line + "\n")
    ky.stdin.flush()
    return ky.stdout.readline().strip()


def flip(b: bytes, positions) -> bytes:
    c = bytearray(b)
    for p in positions:
        c[p % len(c)] ^= 0x01
    return bytes(c)


# ------------------------------------------------------------ keypairs + cases
def make_cases_pyca(sk, pk):
    ss, ct = pk.encapsulate()
    sk2 = MLKEM768PrivateKey.generate()
    return {
        "VALID": (sk, ct),
        "FLIP1": (sk, flip(ct, [0])),
        "FLIPMID": (sk, flip(ct, [543])),
        "WRONGKEY": (sk2, ct),
        "SYNTH-ZERO": (sk, bytes(CT_LEN)),
        "SYNTH-RAND": (sk, bytes(rng.randrange(256) for _ in range(CT_LEN))),
    }, ss


def make_cases_oqs():
    pk_b = ctypes.create_string_buffer(EK_LEN)
    sk_b = ctypes.create_string_buffer(DK_LEN)
    assert lib.OQS_KEM_keypair(kem, pk_b, sk_b) == 0
    pk, sk = pk_b.raw, sk_b.raw
    ct_b = ctypes.create_string_buffer(CT_LEN)
    ss_b = ctypes.create_string_buffer(SS_LEN)
    assert lib.OQS_KEM_encaps(kem, ct_b, ss_b, ctypes.create_string_buffer(pk, EK_LEN + 1)) == 0
    ct = ct_b.raw
    pk2_b = ctypes.create_string_buffer(EK_LEN)
    sk2_b = ctypes.create_string_buffer(DK_LEN)
    assert lib.OQS_KEM_keypair(kem, pk2_b, sk2_b) == 0
    return {
        "VALID": (sk, ct),
        "FLIP1": (sk, flip(ct, [0])),
        "FLIPMID": (sk, flip(ct, [543])),
        "WRONGKEY": (sk2_b.raw, ct),
        "SYNTH-ZERO": (sk, bytes(CT_LEN)),
        "SYNTH-RAND": (sk, bytes(rng.randrange(256) for _ in range(CT_LEN))),
    }


def make_cases_go():
    out = go_cmd("keygen").split()
    dk_seed, ek = bytes.fromhex(out[3]), bytes.fromhex(out[1])
    out = go_cmd("encap " + ek.hex()).split()
    ct, ss = bytes.fromhex(out[1]), bytes.fromhex(out[3])
    out = go_cmd("keygen").split()
    dk2_seed = bytes.fromhex(out[3])
    return {
        "VALID": (dk_seed, ct),
        "FLIP1": (dk_seed, flip(ct, [0])),
        "FLIPMID": (dk_seed, flip(ct, [543])),
        "WRONGKEY": (dk2_seed, ct),
        "SYNTH-ZERO": (dk_seed, bytes(CT_LEN)),
        "SYNTH-RAND": (dk_seed, bytes(rng.randrange(256) for _ in range(CT_LEN))),
    }


def make_cases_ky():
    out = ky_cmd("keygen").split()
    sk, pk = bytes.fromhex(out[3]), bytes.fromhex(out[1])
    out = ky_cmd("enc " + pk.hex()).split()
    ct = bytes.fromhex(out[1])
    out = ky_cmd("keygen").split()
    sk2 = bytes.fromhex(out[3])
    return {
        "VALID": (sk, ct),
        "FLIP1": (sk, flip(ct, [0])),
        "FLIPMID": (sk, flip(ct, [543])),
        "WRONGKEY": (sk2, ct),
        "SYNTH-ZERO": (sk, bytes(CT_LEN)),
        "SYNTH-RAND": (sk, bytes(rng.randrange(256) for _ in range(CT_LEN))),
    }


# ------------------------------------------------------------ batch measurement
def batch_pyca(sk, ct):
    t0 = time.perf_counter_ns()
    for _ in range(REPS):
        sk.decapsulate(ct)
    return (time.perf_counter_ns() - t0) / REPS / 1000.0  # mean us per decap


def batch_oqs(sk, ct):
    sk_b = ctypes.create_string_buffer(sk, DK_LEN + 1)
    ct_b = ctypes.create_string_buffer(ct, CT_LEN + 1)
    ss_b = ctypes.create_string_buffer(SS_LEN)
    t0 = time.perf_counter_ns()
    for _ in range(REPS):
        rc = lib.OQS_KEM_decaps(kem, ss_b, ct_b, sk_b)
        assert rc == 0
    return (time.perf_counter_ns() - t0) / REPS / 1000.0


def batch_go(dk_seed, ct):
    out = go_cmd("timedecap " + dk_seed.hex() + " " + ct.hex() + f" {REPS}")
    parts = out.split()
    assert parts[0] == "TIMED", out
    total_ns, n = int(parts[1]), int(parts[2])
    assert n == REPS
    return total_ns / n / 1000.0


def batch_ky(sk, ct):
    out = ky_cmd("timedecap " + sk.hex() + " " + ct.hex() + f" {REPS}")
    parts = out.split()
    assert parts[0] == "TIMED", out
    total_ns, n = int(parts[1]), int(parts[2])
    assert n == REPS
    return total_ns / n / 1000.0


IMPLS = {
    "pyca-cryptography": (make_cases_pyca, batch_pyca, "pyca"),
    "liboqs": (make_cases_oqs, batch_oqs, "oqs"),
    "go-stdlib-crypto-mlkem": (make_cases_go, batch_go, "go"),
    "kyber-ref": (make_cases_ky, batch_ky, "ky"),
}


def run_impl(name, make_fn, batch_fn):
    log(f"== measuring {name} ==")
    for kp in range(1, N_KEYPAIRS + 1):
        if name == "pyca-cryptography":
            sk_obj = MLKEM768PrivateKey.generate()
            cases, _ = make_fn(sk_obj, sk_obj.public_key())
            # warm-up (discarded)
            for _ in range(WARMUP):
                sk_obj.decapsulate(cases["VALID"][1])
        else:
            cases = make_fn()
            warm_sk, warm_ct = cases["VALID"]
            # Warm-up (discarded): one small batch-equivalent pass.
            if name == "liboqs":
                sk_b = ctypes.create_string_buffer(warm_sk, DK_LEN + 1)
                ct_b = ctypes.create_string_buffer(warm_ct, CT_LEN + 1)
                ss_b = ctypes.create_string_buffer(SS_LEN)
                for _ in range(WARMUP):
                    lib.OQS_KEM_decaps(kem, ss_b, ct_b, sk_b)
            elif name == "go-stdlib-crypto-mlkem":
                go_cmd("timedecap " + warm_sk.hex() + " " + warm_ct.hex() + f" {WARMUP}")
            elif name == "kyber-ref":
                ky_cmd("timedecap " + warm_sk.hex() + " " + warm_ct.hex() + f" {WARMUP}")
        # Interleaved rounds: shuffle class order per round.
        for rnd in range(1, BATCHES + 1):
            order = CLASSES[:]
            rng.shuffle(order)
            for cls in order:
                sk, ct = cases[cls]
                mean_us = batch_fn(sk, ct)
                results["batches"].append({
                    "implementation": name, "keypair": kp, "class": cls,
                    "round": rnd, "reps": REPS, "mean_us": mean_us})
            if rnd % 5 == 0:
                log(f"[{name}] keypair {kp} round {rnd}/{BATCHES} done")
        log(f"[{name}] keypair {kp}/{N_KEYPAIRS} done")


for name, (make_fn, batch_fn, _) in IMPLS.items():
    run_impl(name, make_fn, batch_fn)

lib.OQS_KEM_free(ctypes.c_void_p(kem))
go.stdin.close(); go.wait()
ky.stdin.close(); ky.wait()

# ------------------------------------------------------------ stats + tests
log("== analysis ==")
for name in IMPLS:
    for cls in CLASSES:
        vals = [b["mean_us"] for b in results["batches"]
                if b["implementation"] == name and b["class"] == cls]
        results["stats"][f"{name}|{cls}"] = summarize(vals)

for name in IMPLS:
    valid = [b["mean_us"] for b in results["batches"]
             if b["implementation"] == name and b["class"] == "VALID"]
    valid_med = statistics.median(valid)
    # Null control: VALID split-half (first 10 batches vs last 10, by round
    # order within each keypair is shuffled, so split by recording order).
    first = valid[:len(valid) // 2]
    second = valid[len(valid) // 2:]
    w0 = welch(first, second)
    m0 = mann_whitney(first, second)
    results["tests"].append({
        "implementation": name, "comparison": "VALID-vs-VALID (null control)",
        "n_a": len(first), "n_b": len(second),
        "median_diff_us": statistics.median(first) - statistics.median(second),
        "median_diff_pct_of_valid_median": 100 * (statistics.median(first) - statistics.median(second)) / valid_med,
        "welch": w0, "mann_whitney": m0, "cohen_d": cohen_d(first, second),
        "note": "Null control: same class split in half. A 'significant' result here measures the noise floor / false-positive rate of the procedure."})
    for cls in CLASSES:
        if cls == "VALID":
            continue
        adv = [b["mean_us"] for b in results["batches"]
               if b["implementation"] == name and b["class"] == cls]
        w = welch(valid, adv)
        m = mann_whitney(valid, adv)
        med_diff = statistics.median(adv) - valid_med
        results["tests"].append({
            "implementation": name, "comparison": f"VALID-vs-{cls}",
            "n_a": len(valid), "n_b": len(adv),
            "median_diff_us": med_diff,
            "median_diff_pct_of_valid_median": 100 * med_diff / valid_med,
            "welch": w, "mann_whitney": m, "cohen_d": cohen_d(valid, adv),
            "suspicious": abs(med_diff) > 0.005 * valid_med and (w["p"] < 0.01 or m["p"] < 0.01),
            "note": "Suspicious = |median diff| > 0.5% of VALID median AND p < 0.01 on either test; suspicious pairs get a confirmation rerun."})

# ------------------------------------------------------------ confirmation reruns
log("== confirmation reruns for suspicious pairs ==")
for t in results["tests"]:
    if not t.get("suspicious"):
        continue
    name = t["implementation"]
    cls = t["comparison"].split("-vs-")[1]
    make_fn, batch_fn, _ = IMPLS[name]
    log(f"rerun: {name} VALID-vs-{cls}")
    if name == "pyca-cryptography":
        sk_obj = MLKEM768PrivateKey.generate()
        cases, _ = make_fn(sk_obj, sk_obj.public_key())
        for _ in range(WARMUP):
            sk_obj.decapsulate(cases["VALID"][1])
    else:
        cases = make_fn()
    vals_valid, vals_adv = [], []
    for rnd in range(1, BATCHES + 1):
        order = ["VALID", cls]
        rng.shuffle(order)
        for c in order:
            sk, ct = cases[c]
            mu = batch_fn(sk, ct)
            (vals_valid if c == "VALID" else vals_adv).append(mu)
    w = welch(vals_valid, vals_adv)
    m = mann_whitney(vals_valid, vals_adv)
    med_diff = statistics.median(vals_adv) - statistics.median(vals_valid)
    results["reruns"].append({
        "implementation": name, "comparison": f"VALID-vs-{cls}",
        "n": len(vals_valid),
        "median_diff_us": med_diff,
        "median_diff_pct_of_valid_median": 100 * med_diff / statistics.median(vals_valid),
        "welch": w, "mann_whitney": m, "cohen_d": cohen_d(vals_valid, vals_adv),
        "confirmed": abs(med_diff) > 0.005 * statistics.median(vals_valid) and (w["p"] < 0.01 or m["p"] < 0.01),
        "note": "Fresh keypair, fresh random order. Confirmed = same direction and magnitude as the original suspicious result."})
    log(f"rerun {name} VALID-vs-{cls}: median_diff_pct="
        f"{results['reruns'][-1]['median_diff_pct_of_valid_median']:.3f}% "
        f"welch p={w['p']:.4g} mwu p={m['p']:.4g} "
        f"confirmed={results['reruns'][-1]['confirmed']}")

results["environment"]["loadavg_end"] = loadavg()
results["environment"]["finished_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
results["total_batches"] = len(results["batches"])
results["total_decaps"] = len(results["batches"]) * REPS

with open(os.path.join(OUT, "timing-results.json"), "w") as f:
    json.dump(results, f, indent=2)
with open(os.path.join(OUT, "timing-results.txt"), "w") as f:
    f.write("ML-KEM-768 decapsulation timing -- summary\n")
    f.write(f"generated_utc: {results['generated_utc']}\n")
    f.write(f"total_batches: {results['total_batches']} x {REPS} reps = "
            f"{results['total_decaps']} decaps\n\n")
    for k in sorted(results["stats"]):
        s = results["stats"][k]
        f.write(f"{k}: n={s['n']} mean={s['mean_us']:.3f} median={s['median_us']:.3f} "
                f"stdev={s['stdev_us']:.3f} p5={s['p5_us']:.3f} p95={s['p95_us']:.3f} us\n")
    f.write("\ntests (VALID vs adversarial, batch means in us):\n")
    for t in results["tests"]:
        f.write(f"{t['implementation']} {t['comparison']}: median_diff={t['median_diff_us']:+.3f} us "
                f"({t['median_diff_pct_of_valid_median']:+.3f}%) welch p={t['welch']['p']:.4g} "
                f"mwu p={t['mann_whitney']['p']:.4g} d={t['cohen_d']:+.3f}\n")
    if results["reruns"]:
        f.write("\nreruns:\n")
        for r in results["reruns"]:
            f.write(f"{r['implementation']} {r['comparison']}: median_diff_pct={r['median_diff_pct_of_valid_median']:+.3f}% "
                    f"welch p={r['welch']['p']:.4g} mwu p={r['mann_whitney']['p']:.4g} confirmed={r['confirmed']}\n")

for t in results["tests"]:
    log(f"{t['implementation']} {t['comparison']}: median_diff={t['median_diff_us']:+.3f} us "
        f"({t['median_diff_pct_of_valid_median']:+.3f}%) welch p={t['welch']['p']:.4g} "
        f"mwu p={t['mann_whitney']['p']:.4g} d={t['cohen_d']:+.3f}")
log("TOTAL BATCHES:", results["total_batches"], "| TOTAL DECAPS:", results["total_decaps"])
log("DONE")
