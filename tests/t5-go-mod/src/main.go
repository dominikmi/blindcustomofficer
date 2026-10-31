package main

import (
	"io"
	"os"

	"github.com/andybalholm/brotli"
)

// Minimal brotli decompressor: stdin -> stdout.
func main() {
	if _, err := io.Copy(os.Stdout, brotli.NewReader(os.Stdin)); err != nil {
		os.Exit(2)
	}
}
