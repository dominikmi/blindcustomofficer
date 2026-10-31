#!/usr/bin/env bash
# Pipeline for the CVE-2026-111497 SCA blind-spot corpus.
# Usage: pipeline.sh <build|sbom|scan|env|all> [test-dir-name | all]
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TESTS_DIR="$ROOT/tests"
IMAGE_PREFIX="sca-blind"

targets() {
    if [[ "${2:-all}" == "all" ]]; then
        ls "$TESTS_DIR"
    else
        echo "$2"
    fi
}

log() { printf '[pipeline] %s\n' "$*"; }

# Image name = Dockerfile suffix: Dockerfile.t15-base -> sca-blind/t15-base.
# Files ending in -base build first (reverse sort puts them ahead).
img_for() { basename "$1" | sed 's/^Dockerfile\.//'; }

build() {
    local t df suffix
    for t in $(targets x "${1:-all}"); do
        ls "$TESTS_DIR/$t"/Dockerfile.* >/dev/null 2>&1 || { log "SKIP $t (no Dockerfile)"; continue; }
        for df in $(ls -r "$TESTS_DIR/$t"/Dockerfile.*); do
            suffix=$(img_for "$df")
            log "BUILD $t [$suffix]"
            docker build -f "$df" -t "$IMAGE_PREFIX/$suffix:latest" "$TESTS_DIR/$t" \
                > "$TESTS_DIR/$t/results/build.$suffix.log" 2>&1 \
                && log "  ok" \
                || log "  FAILED (see $TESTS_DIR/$t/results/build.$suffix.log)"
        done
    done
}

# The scan target for a test dir = image of its non-base Dockerfile.
# Match on basename only — dir names may themselves contain "-base".
main_img() {
    local df base
    for df in "$TESTS_DIR/$1"/Dockerfile.*; do
        base=$(basename "$df")
        [[ "$base" != *-base ]] && { img_for "$df"; return; }
    done
}

sbom() {
    local t img
    for t in $(targets x "${1:-all}"); do
        img=$(main_img "$t")
        [[ -n "$img" ]] && docker image inspect "$IMAGE_PREFIX/$img:latest" >/dev/null 2>&1 \
            || { log "SKIP $t (no image)"; continue; }
        log "SBOM $t [$img]"
        syft "docker:$IMAGE_PREFIX/$img:latest" -o json > "$TESTS_DIR/$t/results/syft.sbom.json" 2>/dev/null \
            || log "  syft failed"
        # CycloneDX 1.6 — the version Snyk's SBOM ingestion accepts (default is 1.7).
        syft "docker:$IMAGE_PREFIX/$img:latest" -o cyclonedx-json@1.6 > "$TESTS_DIR/$t/results/syft.cdx16.json" 2>/dev/null \
            || log "  syft(cdx16) failed"
    done
}

scan() {
    local t r img
    for t in $(targets x "${1:-all}"); do
        img=$(main_img "$t")
        [[ -n "$img" ]] && docker image inspect "$IMAGE_PREFIX/$img:latest" >/dev/null 2>&1 \
            || { log "SKIP $t (no image)"; continue; }
        r="$TESTS_DIR/$t/results"
        log "SCAN $t [$img]"
        grype "docker:$IMAGE_PREFIX/$img:latest" -o json > "$r/grype.image.json" 2>"$r/grype.image.err" \
            || log "  grype(image) failed"
        [[ -s "$r/syft.sbom.json" ]] && \
            grype "sbom:$r/syft.sbom.json" -o json > "$r/grype.sbom.json" 2>"$r/grype.sbom.err" \
            || log "  grype(sbom) skipped/failed"
        trivy image --scanners vuln --format json -o "$r/trivy.json" "$IMAGE_PREFIX/$img:latest" \
            > /dev/null 2>"$r/trivy.err" || log "  trivy failed"
        # app-vulns is on by default; nested-jars-depth helps vs shaded jars.
        snyk container test "$IMAGE_PREFIX/$img:latest" --json \
            --nested-jars-depth=3 > "$r/snyk.json" 2>"$r/snyk.err"; \
            [[ $? -gt 1 ]] && log "  snyk failed"   # exit 1 = vulns found, >1 = error
        # Snyk's own SBOM ingestion (CycloneDX 1.6). Enterprise-gated — may 403.
        [[ -s "$r/syft.cdx16.json" ]] && \
            snyk sbom test --experimental --file="$r/syft.cdx16.json" --json \
                > "$r/snyk.sbom.json" 2>"$r/snyk.sbom.err"; \
            [[ $? -gt 1 ]] && log "  snyk sbom test failed (plan-gated?)"
        # scout v1.27 formats: sarif|spdx|gitlab|markdown (no plain json)
        docker scout cves "$IMAGE_PREFIX/$img:latest" --format sarif > "$r/scout.sarif.json" 2>"$r/scout.err" \
            || docker scout cves "$IMAGE_PREFIX/$img:latest" > "$r/scout.txt" 2>>"$r/scout.err" \
            || log "  scout failed"
        rm -f "$r/scout.json"   # remove stale help-text output from earlier runs
    done
}

# Snyk unmanaged/binary scan: export the image rootfs and scan the bare files.
unmanaged() {
    local t img r cid tmp
    for t in $(targets x "${1:-all}"); do
        img=$(main_img "$t")
        [[ -n "$img" ]] && docker image inspect "$IMAGE_PREFIX/$img:latest" >/dev/null 2>&1 \
            || { log "SKIP $t (no image)"; continue; }
        r="$TESTS_DIR/$t/results"
        tmp=$(mktemp -d)
        log "UNMANAGED $t [$img]"
        cid=$(docker create "$IMAGE_PREFIX/$img:latest")
        if docker export "$cid" | tar -xf - -C "$tmp" 2>/dev/null; then
            snyk test --unmanaged "$tmp" --json > "$r/snyk.unmanaged.json" 2>"$r/snyk.unmanaged.err"; \
                [[ $? -gt 1 ]] && log "  snyk unmanaged failed"
        else
            log "  rootfs export failed"
        fi
        docker rm "$cid" >/dev/null 2>&1
        rm -rf "$tmp"
    done
}

env_capture() {
    {
        echo '{'
        echo "  \"captured\": \"$(date -u +%FT%TZ)\","
        echo "  \"syft\": \"$(syft version 2>/dev/null | awk -F': +' '/Version/{print $2}')\","
        echo "  \"grype\": \"$(grype version 2>/dev/null | awk -F': +' '/Version/{print $2}')\","
        echo "  \"trivy\": \"$(trivy version 2>/dev/null | awk '/Version/{print $2; exit}')\","
        echo "  \"snyk\": \"$(snyk --version 2>/dev/null)\","
        echo "  \"docker_scout\": \"$(docker scout version 2>/dev/null | awk '/version/{print $2}')\","
        echo '  "grype_db": '"$(grype db status -o json 2>/dev/null || echo null)"
        echo '}'
    } > "$ROOT/results/_environment.json"
    log "env -> results/_environment.json"
}

case "${1:-all}" in
    build) build "${2:-all}" ;;
    sbom)  sbom  "${2:-all}" ;;
    scan)  scan  "${2:-all}" ;;
    unmanaged) unmanaged "${2:-all}" ;;
    env)   env_capture ;;
    all)   env_capture; build all; sbom all; scan all; unmanaged all ;;
    *)     echo "usage: $0 <build|sbom|scan|unmanaged|env|all> [test|all]" >&2; exit 64 ;;
esac
