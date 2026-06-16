// Copyright (C) 2026 mohamedation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/mohamedation/PwnedCheck/internal/checker"
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "PwnedCheck\n")
		fmt.Fprintf(os.Stderr, "by mohamedation - v%s\n\n", "1.0.0")
		fmt.Fprintf(os.Stderr, "Usage: pwnedcheck [options] [password ...]\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		fmt.Fprintf(os.Stderr, "  -i, --input <string>     Input file containing passwords or JSON export (default \"passwords.txt\")\n")
		fmt.Fprintf(os.Stderr, "  -bw, --bitwarden         Treat input file as a Bitwarden password-protected encrypted JSON export\n")
		fmt.Fprintf(os.Stderr, "  -H, --hashed             Input file contains pre-computed SHA-1 hashes instead of plaintext\n")
		fmt.Fprintf(os.Stderr, "  -x, --hide               Hide plaintext passwords from console output\n")
		fmt.Fprintf(os.Stderr, "  -s, --stats              Show runtime and result summary after completion\n")
		fmt.Fprintf(os.Stderr, "  -v, --verbose            Print each HIBP request to show exactly what is sent to the API\n")
		fmt.Fprintf(os.Stderr, "  -c, --credits            Show credits\n")
		fmt.Fprintf(os.Stderr, "  -h, --help               Show help\n")
	}

	var (
		inputFile    string
		hashed       bool
		hidePassword bool
		showStats    bool
		bitwarden    bool
		verbose      bool
		credits      bool
	)

	flag.StringVar(&inputFile, "i", "passwords.txt", "")
	flag.StringVar(&inputFile, "input", "passwords.txt", "")
	flag.BoolVar(&hashed, "hashed", false, "")
	flag.BoolVar(&hashed, "H", false, "")
	flag.BoolVar(&hidePassword, "hide", false, "")
	flag.BoolVar(&hidePassword, "x", false, "")
	flag.BoolVar(&showStats, "stats", false, "")
	flag.BoolVar(&showStats, "s", false, "")
	flag.BoolVar(&bitwarden, "bw", false, "")
	flag.BoolVar(&bitwarden, "bitwarden", false, "")
	flag.BoolVar(&verbose, "v", false, "")
	flag.BoolVar(&verbose, "verbose", false, "")
	flag.BoolVar(&credits, "c", false, "")
	flag.BoolVar(&credits, "credits", false, "")

	flag.Parse()

	if credits {
		fmt.Println("PwnedCheck - v1.0.0\n\nby mohamedation\nReal work is done by Troy Hunt and the HIBP API.")
		os.Exit(0)
	}

	cfg := checker.Config{
		InputFile:    inputFile,
		IsHashed:     hashed,
		HidePassword: hidePassword,
		ShowStats:    showStats,
		Bitwarden:    bitwarden,
		Verbose:      verbose,
		Args:         flag.Args(),
	}

	os.Exit(checker.Run(cfg))
}
