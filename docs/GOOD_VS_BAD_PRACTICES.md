# Good vs Bad: Docker builds that surface every vulnerability vs ones that hide them

Rules derived from the CVE-2026-111497 corpus (`tests/`), where 9 of 15
delivery vectors left vulnerable brotli **completely invisible** to
Syft/Grype/Trivy/Snyk/Scout.

---

## If you want 100% vulnerability surface visibility — build this way

### Dockerfile rules

```dockerfile
# 1. Pin the base by digest — never a floating tag
FROM debian:bookworm-slim@sha256:<digest>

# 2. Index refresh and install in the SAME layer — the index can't go stale
RUN apt-get update && \
    apt-get install -y --no-install-recommends libbrotli1 && \
    rm -rf /var/lib/apt/lists/*

# 3. Bust the apt-cache layer deliberately on rebuilds
#    Layer cache keys on instruction TEXT — apt-get update's output changes
#    daily but its text never does, so it caches forever. Varying an ARG
#    changes the instruction → cache miss → real re-fetch. One changed layer
#    also cascades: every layer AFTER it rebuilds too, so installs actually
#    resolve the fresh index. Pass a UNIQUE value per build — $CI_COMMIT_SHA
#    or build number; a bare date fails when builds run >1x/day.
ARG APT_EPOCH=dev
RUN echo "pkg index epoch: $APT_EPOCH" && apt-get update

# 4. Multi-stage: ship only the runtime artifact, never the toolchain
FROM debian:bookworm-slim@sha256:<digest>
COPY --from=build /out/app /usr/local/bin/app

# 5. Never delete package metadata (dist-info, /var/lib/dpkg/*, jar META-INF).
#    Slim by NOT installing — not by erasing the record of what is installed.
```

### CI gates — this is where visibility is actually enforced

```yaml
build:
  - docker build --build-arg APT_EPOCH=$CI_COMMIT_SHA --provenance=true -t app:$SHA .
sbom:
  - docker create --name tmp app:$SHA && docker export tmp | \
      syft - -o cyclonedx-json@1.6 > sbom.cdx.json && docker rm tmp
  # the SBOM is a baseline inventory — not ground truth (see rule B3)
scan:
  - grype app:$SHA --fail-on high
  - grype sbom:sbom.cdx.json          # match against the emitted SBOM too
  - trivy image app:$SHA --severity HIGH,CRITICAL
dark_matter_audit:                   # the gate nobody runs.
  # "dark matter" = files on disk that NO package manager claims.
  # brotli is this week's specimen — the class is generic:
  # any .so/.a/ELF/jar/vendored source with no owner record.
  - docker run --rm app:$SHA sh -c '\
      comm -23 \
        <(find / -xdev -type f \( -name "*.so*" -o -name "*.a" -o -name "*.jar" -o -perm -111 \) | sort) \
        <(dpkg-query -L | sort -u)' > unmanaged-files.txt
  - # dpkg images: dpkg-query -L = "what the PM owns"; comm -23 = disk - owned.
    # apk images:  apk info -L;   rpm: rpm -qal.
  - # diff unmanaged-files.txt vs sbom.cdx.json components:
    #   present on disk + absent in SBOM = invisible to every scanner
  - # per-ecosystem same audit: site-packages entries missing dist-info RECORD,
    # go binaries without readable build-info, jars without META-INF/maven
rescan_on_advisories:
  - # nightly: grype sbom:sbom.cdx.json again — new advisories land
    # days/weeks after a CVE; a clean scan at CVE+2d means little
```

---

## The bad patterns — and how to fix each

### B1. `RUN apt-get update` as its own layer → stale index forever

```dockerfile
RUN apt-get update          # cached once at first build
RUN apt-get install -y foo  # resolves whatever that stale index knows
```

**What it causes:** every rebuild installs packages from the *first* build's
index. "We rebuilt" ≠ "we re-fetched" — the fix published last week never
reaches you. *(proven: `t14-stale-index`)*

**Fix:** `apt-get update && apt-get install` in one RUN; pass
`--build-arg APT_EPOCH` or `--no-cache` on rebuilds.

### B2. `FROM base:latest` → base-tag drift

```dockerfile
FROM myorg/base:latest      # baked months ago, still called "latest"
COPY app.sh /usr/local/bin/
```

**What it causes:** `latest` resolves at pull time; `docker build` reuses the
*cached* base without re-resolving. Fresh builds run on whatever `latest`
meant last time it was pulled — months-old packages with known CVEs baked in.
*(proven: `t15-cached-base`)*

**Fix:** pin `@sha256:<digest>`; put the base on a scheduled rebuild and let
Renovate/Dependabot bump digests into child repos.

### B3. Vendored deps with no metadata → the dark matter

```dockerfile
RUN curl -fsSL https://github.com/google/brotli/archive/v1.1.0.tar.gz | tar xz && \
    cmake -B build && cmake --install build --prefix /usr/local
```

**What it causes:** `.so` files land with **zero inventory record** — every
scanner in our matrix missed them. This isn't brotli-specific: it's *any*
component that reaches disk outside a package manager — `pillow.libs/` natives
inside wheels (t13), copied Go source (t6), shaded+relocated jars (t8),
embedded libs inside release binaries (t10). The class of vulns you'll never
see is unbounded; brotli is just the one we instrumented.

**GOOD — vendored, but inventoried:**

```dockerfile
# Option A: prefer the distro package — dpkg record = scanner-visible
RUN apt-get update && apt-get install -y --no-install-recommends libbrotli1

# Option B: must build from source → leave a machine-readable trail
FROM build AS runtime
COPY --from=build /usr/local/lib/libbrotli*.so* /opt/app/lib/
# ship a manifest next to the artifact — the audit gate (step 5) verifies it
RUN printf 'pkg:generic/brotli@1.1.0 source=github/google/brotli sha256=<pinned>\n' \
    > /opt/app/lib/VENDOR.txt
COPY --from=build /out/vendor-sbom.json /opt/app/vendor-sbom.json
```

**Seen in the wild:**
- [`php/frankenphp` — Dockerfile](https://github.com/php/frankenphp/blob/main/Dockerfile) — compiles brotli from source at `/usr/local/src/brotli`, comment cites CVE-2026-111497
- [`telegramdesktop/tdesktop` — Telegram/build/docker/centos_env/Dockerfile](https://github.com/telegramdesktop/tdesktop/blob/dev/Telegram/build/docker/centos_env/Dockerfile)
- [`ArchiveTeam/wget-lua` — Dockerfile](https://github.com/ArchiveTeam/wget-lua/blob/master/Dockerfile)

**Fixes:**
- Prefer the **distro package** — dpkg/apk record = scanner-visible.
- Must build from source → keep a machine-readable inventory at build time
  (CI-side `syft` export above) *and* run the dark-matter audit — the SBOM
  generator misses the same files, so the **diff of "files on disk vs packages
  known" is the actual control**, not the SBOM alone.
- Go: don't copy dep source in-tree; keep the module so build-info records it
  (t5 enumerable vs t6 invisible). Caveat: enumerable ≠ flaggable while no
  advisory exists.
- Java: don't shade META-INF away; keep `dependency-reduced-pom.xml` or embed
  an SBOM file in the jar.

### B4. Deleting metadata "to slim the image" → manufactured false negative

```dockerfile
RUN apt-get install -y libbrotli1 && rm -rf /var/lib/dpkg/info/libbrotli1.*
RUN pip install Brotli==1.1.0 && rm -rf /usr/local/lib/python*/site-packages/Brotli-*.dist-info
```

**What it causes:** files remain, the inventory record dies — scanners report
nothing for a vuln that's fully present. *(proven: `t9`, `t11`)*

**Seen in the wild:** `rm -rf *dist-info` metadata scrubs —
- [`prowler-cloud/prowler` — api/Dockerfile](https://github.com/prowler-cloud/prowler/blob/main/api/Dockerfile) and [mcp_server/Dockerfile](https://github.com/prowler-cloud/prowler/blob/main/mcp_server/Dockerfile) — in a security scanner's own image
- [`ministackorg/ministack` — Dockerfile](https://github.com/ministackorg/ministack/blob/main/Dockerfile)
- [`openreplay/openreplay` — api/Dockerfile_alerts](https://github.com/openreplay/openreplay/blob/main/api/Dockerfile_alerts)
- [`PaddlePaddle/FastDeploy` — dockerfiles/Dockerfile.xpu](https://github.com/PaddlePaddle/FastDeploy/blob/develop/dockerfiles/Dockerfile.xpu)
- [`plexe-ai/plexe` — Dockerfile](https://github.com/plexe-ai/plexe/blob/main/Dockerfile)

**GOOD — slim by not installing, never by erasing the record:**

```dockerfile
# pip: install once, keep every dist-info
RUN pip install --no-cache-dir Brotli==1.2.1
# want it lean? use a venv + multi-stage copy — the record travels with the files
FROM python:3.12-slim-bookworm
COPY --from=build /opt/venv /opt/venv   # venv carries site-packages WITH dist-info
ENV PATH="/opt/venv/bin:$PATH"
```

**Fix:** never delete `*.dist-info`, `/var/lib/dpkg/*`, or jar `META-INF`.
Slim by not installing, or by multi-stage `COPY --from=build`.

### B5. "We rebuilt the image" as a patch claim → confidence without coverage

**What it causes:** rebuild on stale index + stale base = same vulnerable
image with a new timestamp. Worst failure mode: scanners flag it (if the
record survived) while the team believes it's patched.

**GOOD — a rebuild that actually re-fetches:**

```dockerfile
ARG APT_EPOCH=dev
ARG BASE_DIGEST
FROM debian:bookworm-slim@sha256:${BASE_DIGEST}
RUN apt-get update && apt-get install -y libbrotli1
```

```bash
# CI: fresh base digest + fresh index epoch, every rebuild
docker build --build-arg APT_EPOCH=$CI_COMMIT_SHA \
             --build-arg BASE_DIGEST=$(docker buildx imagetools inspect debian:bookworm-slim \
                                       --format '{{.Manifest.Digest}}') -t app:$SHA .
# verify the claim in the SAME pipeline — don't trust the timestamp:
docker run --rm app:$SHA dpkg -l | grep libbrotli   # assert >= fixed version
```

**Fix:** a rebuild only patches if the *inputs* changed — index epoch arg,
base digest bump, or `--no-cache`. Verify by inspecting the built image
(`dpkg -l`, `pip show`, `node --version`), not by trusting the CI timestamp.

---

## Quick reference

| bad pattern | what it really does | fix |
|---|---|---|
| `RUN apt-get update` own layer | freezes pkg index at first build | update+install in one RUN; epoch arg |
| `FROM x:latest` | cached base reused indefinitely | `@sha256:` pin + scheduled rebase |
| source build, no inventory | component invisible to scanners | SBOM + files-vs-packages audit |
| wheels w/ vendored natives | `.libs/*.so` has no metadata | audit `.libs/`/`.dylibs/` in CI |
| copied/vendored Go source | dep vanishes from build-info | keep it a module |
| shaded jar, META-INF stripped | vuln classes w/o identity | keep dep-reduced pom / embedded SBOM |
| `rm` dist-info/dpkg records | hand-made false negative | never delete package metadata |
| rebuild ≠ patch | new layers, same old content | fresh index + fresh base + verify |
