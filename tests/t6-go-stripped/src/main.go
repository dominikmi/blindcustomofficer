package main

import (
	"io"
	"os"

	"scablind/t6/internal/brotli"
)

// Minimal brotli decompressor: stdin -> stdout.
// The brotli code was copied in-tree (vendored source) — no external module
// appears in go build info at all.
func main() {
	if _, err := io.Copy(os.Stdout, brotli.NewReader(os.Stdin)); err != nil {
		os.Exit(2)
	}
}
