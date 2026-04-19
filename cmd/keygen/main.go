package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"os"

	"encrypt-proxy/internal/tunnel"
)

func main() {
	out := flag.String("out", "", "base path for key files (e.g. ./data/server → data/server.key + data/server.pub)")
	flag.Parse()

	if *out == "" {
		fmt.Fprintln(os.Stderr, "usage: keygen -out <base_path>")
		os.Exit(1)
	}

	if err := tunnel.GenerateAndSaveKeypair(*out); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	pub, err := tunnel.LoadServerPubKey(*out + ".pub")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading generated pubkey: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("generated: %s.key  %s.pub\n", *out, *out)
	fmt.Printf("public key: %s\n", base64.StdEncoding.EncodeToString(pub))
}
