package main

import (
	"fmt"
	"os"

	"aidanwoods.dev/go-paseto"
)

func main() {
	privateKey := paseto.NewV4AsymmetricSecretKey()
	publicKey := privateKey.Public()

	_, err := fmt.Fprintf(os.Stdout, "private_hex:\n%s\n\npublic_hex:\n%s\n",
		privateKey.ExportHex(), publicKey.ExportHex())
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "failed to write key output: %v\n", err)
		os.Exit(1)
	}
}
