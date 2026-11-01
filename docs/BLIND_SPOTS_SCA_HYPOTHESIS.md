# SCA Blind-Spot Study: CVE-2026-111497 (Brotli Decoder OOB Write)

Plant the same vulnerability — CVE-2026-111497, the Brotli decoder out-of-bounds write ("broccoli2shell"/"node2shell") — through a dozen delivery vectors (dpkg, source build, vendored .so, static link, Node's bundled brotli, Go/Python/Java deps, scratch, whiteouts), scan every image with Syft/Trivy/Grype/Snyk/Docker Scout, and report exactly which vectors each scanner surfaces and which go blind.

## Why this CVE

CVE-2026-111497 (OOB write in `c/dec/decode.c`, published 2026-10-22, in KEV-watch territory) is the perfect blind-spot specimen because brotli ships through **every** delivery channel: distro package (`libbrotli1`), PyPI (`Brotli`, `brotlicffi` — PYSEC-2026-4322/4323), Maven (`brotli4j <1.24.0`), Go module (`andybalholm/brotli`), .NET runtime, **statically bundled inside the `node`/`bun` binaries** (node <22.23.4 / 24.22.1 / 26.12.1; node 20/23/25 EOL forever-vulnerable), and vendored C sources. One CVE, many vectors → clean single-row-per-vector detection matrix.

Affected: brotli **1.0.3–1.2.0**; fixed in 1.0.10 / 1.1.1 / 1.2.1. Plant versions: **1.1.0** and **1.2.0** (github.com/google/brotli release tarballs).

## Critical methodology control (CVE is ~1 week old)

A scanner "miss" is ambiguous: (a) it couldn't see the component vs (b) its DB hasn't ingested the CVE for that ecosystem yet. Controls:

- **Refresh all DBs at scan start** (`grype db update` — local DB is stale/invalid, built Oct 14; trivy DB already refreshed today). Record `results/_environment.json`: scanner versions + DB build timestamps.
- **Canary gate:** `ctrl-deb` (dpkg-installed vulnerable `libbrotli1`) must surface CVE-2026-111497 in every scanner before any blind-spot verdict is trusted. Per-ecosystem canaries via `grype db search --vuln` / `grype sbom:` on a hand-built SBOM.
- **Two-layer verdict per component:** enumerated? (Syft) → vuln-matched? (scanner). `grype sbom:` on the Syft output decouples matching from enumeration.

## Test corpus — 18 images (`tests/<name>/Dockerfile.<suffix>`)

**Controls** (must fire, or every "miss" below is suspect):

| Image | Vector | Planted payload | Dockerfile |
|---|---|---|---|
| `ctrl-deb` | apt/dpkg record | `libbrotli1 1.0.9-2+b6` via pinned `snapshot.debian.org` | [Dockerfile.ctrl-deb](../tests/ctrl-deb/Dockerfile.ctrl-deb) |
| `ctrl-pip` | pip + dist-info intact | `Brotli==1.1.0` | [Dockerfile.ctrl-pip](../tests/ctrl-pip/Dockerfile.ctrl-pip) |
| `ctrl-node` | stock `node:20-bookworm-slim` | bundled brotli inside `node` binary | [Dockerfile.ctrl-node](../tests/ctrl-node/Dockerfile.ctrl-node) |

**Blind-spot vectors** (same vuln, no usable metadata):

| Image | Vector | Planted payload | Dockerfile |
|---|---|---|---|
| `t1-srcbuild` | cmake build → `/usr/local` + `ldconfig` | `libbrotli*.so.1.1.0`, zero package metadata | [Dockerfile.t1](../tests/t1-srcbuild/Dockerfile.t1) |
| `t2-vendored-so` | `.so` COPY'd to `/opt/app/lib` + rpath'd C decoder | vendor-shipped lib dir | [Dockerfile.t2](../tests/t2-vendored-so/Dockerfile.t2) |
| `t3-static` | decoder statically linked vs `libbrotli*.a` | single ELF — hardest case | [Dockerfile.t3](../tests/t3-static/Dockerfile.t3) |
| `t4-node-scratch` | bare `node` binary in `FROM scratch` | binary fingerprinting only | [Dockerfile.t4](../tests/t4-node-scratch/Dockerfile.t4) |
| `t5-go-mod` | Go app, `andybalholm/brotli v1.2.6` | build-info enumerates, no advisory exists | [Dockerfile.t5](../tests/t5-go-mod/Dockerfile.t5) |
| `t6-go-stripped` | brotli source copied in-tree, stripped | invisible even to `go version -m` | [Dockerfile.t6](../tests/t6-go-stripped/Dockerfile.t6) |
| `t7-jar` | `brotli4j-1.16.0.jar` loose | manifest-based detection | [Dockerfile.t7](../tests/t7-jar/Dockerfile.t7) |
| `t8-shaded` | same dep shaded + relocated, `META-INF/maven` filtered | all three identity hooks erased | [Dockerfile.t8](../tests/t8-shaded/Dockerfile.t8) |
| `t9-py-vendored` | wheel files in site-packages, **dist-info deleted** | byte-identical to ctrl-pip minus record | [Dockerfile.t9](../tests/t9-py-vendored/Dockerfile.t9) |
| `t10-curl-bin` | static musl `curl 8.16.0` (`brotli/1.1.0` compiled in) | embedded-lib visibility | [Dockerfile.t10](../tests/t10-curl-bin/Dockerfile.t10) |
| `t11-dbstrip` | dpkg-installed libbrotli, then status stanza + info files deleted | files remain, record gone | [Dockerfile.t11](../tests/t11-dbstrip/Dockerfile.t11) |
| `t12-distroless` | `.so` payloads in `gcr.io/distroless/base` | no package DB, no shell | [Dockerfile.t12](../tests/t12-distroless/Dockerfile.t12) |
| `t13-pip-transitive` | `uv pip install pillow==13.0.0` | vendored `pillow.libs/libbrotli*-*.so.1.2.0` | [Dockerfile.t13](../tests/t13-pip-transitive/Dockerfile.t13) |

**Malpractice vectors** (vuln visible — process broken):

| Image | Vector | What it proves | Dockerfile |
|---|---|---|---|
| `t14-stale-index` | `apt-get update` in its own cached layer | "rebuilt" ≠ "re-fetched" | [Dockerfile.t14](../tests/t14-stale-index/Dockerfile.t14) |
| `t15-cached-base` | child on stale pre-fix base | base-tag drift | [Dockerfile.t15](../tests/t15-cached-base/Dockerfile.t15) (+ [base](../tests/t15-cached-base/Dockerfile.t15-base)) |

*(Plus `ctrl-patched` — `Brotli==1.2.1` — PoC negative control, added later; not counted in the 18.)*

## Scanning protocol

Per image → `results/<scanner>/<image>.json`:

1. `syft <img> -o json` — enumeration baseline
2. `grype <img> -o json` + `grype sbom:<file>` — matcher decoupled from enumerator
3. `trivy image --scanners vuln --format json`
4. `snyk container test <img> --json` — authenticated as `dominikmi` (verified via `snyk whoami`)
5. `docker scout cves <img> --format json` — verified working (indexed `hello-world`; scout v1.27.0, v1.29.0 available)

## Deliverables

- `tests/` + `ground_truth.yaml` (image → planted component/version/vector/expected-CVE)
- `harness/`: `pipeline.sh` (build / sbom / scan per test or all), `matrix.py`
- `tests/<name>/results/` raw scanner JSON + `_environment.json`
- `report/REPORT.md` + `report/matrix.csv`: single-CVE detection matrix (vector × scanner), enumeration-vs-matching classification, DB-timestamp caveats, and the headline answer: **which delivery vectors of this CVE each scanner cannot see** — with special attention to Node's bundled brotli, since that's the actively-burning real-world case.

## Risks

- DB lag is real and near-certain for some ecosystems at 1-week-old CVE — the canary gate converts "inconclusive" into "proven DB gap" vs "proven detection gap" instead of guessing.
- `ctrl-deb` needs a still-vulnerable distro package: check `apt policy libbrotli1` on pinned bases; fall back to `snapshot.debian.org` dated before the Debian fix (debian-lts-announce/2026/10/msg00049).
- t3 static link and t6 stripped-Go are expected-universally-blind — they're the ceiling reference, not failures.
- Build times: brotli C build is small; maven/go stages are the slow ones; parallelize where possible.
