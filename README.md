# blindcustomofficer

**"Ślepy celnik"** — a test corpus proving that container SCA scanners check
the *manifest*, not the cargo.

Every image in `tests/` plants the **same vulnerability** —
[CVE-2026-111497](https://nvd.nist.gov/vuln/detail/CVE-2026-111497), the
Brotli decoder OOB write ("broccoli2shell" / "HTTP2Shell"; affected:
brotli 1.0.3–1.2.0) — through a **different delivery vector**. Scanned with
Syft + Grype, Trivy, Snyk (container / sbom-test / unmanaged), Docker Scout.

**Result: 9 of 16 vectors invisible to every scanner** — any vector that
removed the package record while keeping the vulnerable bytes.

## What's inside

- `tests/<name>/Dockerfile.<suffix>` — 16 test images (controls,
  blind-spot vectors, build-malpractice cases)
- `harness/pipeline.sh` — build → SBOM → scan, per test or all
- `harness/matrix.py` — aggregates scan JSON into a detection matrix
- `ground_truth.yaml` — what each test plants and what to match

## Quick tour

| test | what it plants | outcome |
|---|---|---|
| ctrl-deb / ctrl-pip / ctrl-node | normal apt / pip / stock node:20 | detected (canaries) |
| t1–t3 | source-built `.so`, vendored `.so`, static ELF | **blind** |
| t4 | bare `node` in FROM scratch | only grype (CPE) |
| t5 / t6 | Go module / vendored Go source | enumerated-but-unmatched / blind |
| t7 / t8 | brotli4j jar / shaded+relocated | only snyk / blind |
| t9 | wheel files, dist-info deleted | blind |
| t10–t12 | static curl / dpkg-scrubbed / distroless | blind |
| **t13** | **`pillow.libs/libbrotli*.so.1.2.0` inside the wheel** | **blind — the flagship case** |
| t14 / t15 | stale apt index / stale base | detected — process failure, not scanner |

## Reproduce

```bash
harness/pipeline.sh all            # build + sbom + scan everything
harness/pipeline.sh build t13      # or single test
```

Blog writeup (PL): *"Ślepy celnik"* — celnik, który sprawdza tylko listę
przewozową.
