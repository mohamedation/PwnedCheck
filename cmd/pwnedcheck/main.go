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
	"io"
	"os"

	"github.com/mohamedation/PwnedCheck/internal/checker"
)

const version = "1.0.1"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	cfg, showCredits, err := parseArgs(args, stderr)
	if err == flag.ErrHelp {
		printUsage(stderr)
		return 0
	}
	if err != nil {
		return 2
	}
	if showCredits {
		printCredits(stdout)
		return 0
	}
	return checker.Run(cfg)
}

func parseArgs(args []string, errOut io.Writer) (checker.Config, bool, error) {
	fs := flag.NewFlagSet("pwnedcheck", flag.ContinueOnError)
	fs.SetOutput(errOut)
	fs.Usage = func() {}

	var (
		inputFile    string
		hashed       bool
		hidePassword bool
		showStats    bool
		bitwarden    bool
		verbose      bool
		credits      bool
	)

	fs.StringVar(&inputFile, "i", "passwords.txt", "")
	fs.StringVar(&inputFile, "input", "passwords.txt", "")
	fs.BoolVar(&hashed, "hashed", false, "")
	fs.BoolVar(&hashed, "H", false, "")
	fs.BoolVar(&hidePassword, "hide", false, "")
	fs.BoolVar(&hidePassword, "x", false, "")
	fs.BoolVar(&showStats, "stats", false, "")
	fs.BoolVar(&showStats, "s", false, "")
	fs.BoolVar(&bitwarden, "bw", false, "")
	fs.BoolVar(&bitwarden, "bitwarden", false, "")
	fs.BoolVar(&verbose, "v", false, "")
	fs.BoolVar(&verbose, "verbose", false, "")
	fs.BoolVar(&credits, "c", false, "")
	fs.BoolVar(&credits, "credits", false, "")

	if err := fs.Parse(args); err != nil {
		return checker.Config{}, false, err
	}

	return checker.Config{
		InputFile:    inputFile,
		IsHashed:     hashed,
		HidePassword: hidePassword,
		ShowStats:    showStats,
		Bitwarden:    bitwarden,
		Verbose:      verbose,
		Args:         fs.Args(),
	}, credits, nil
}

func printUsage(w io.Writer) {
	fmt.Fprintf(w, "PwnedCheck\n")
	fmt.Fprintf(w, "by mohamedation - v%s\n\n", version)
	fmt.Fprintf(w, "Usage: pwnedcheck [options] [password ...]\n\n")
	fmt.Fprintf(w, "Options:\n")
	fmt.Fprintf(w, "  -i, --input <string>     Input file containing passwords or JSON export (default \"passwords.txt\")\n")
	fmt.Fprintf(w, "  -bw, --bitwarden         Treat input file as a Bitwarden password-protected encrypted JSON export\n")
	fmt.Fprintf(w, "  -H, --hashed             Input file contains pre-computed SHA-1 hashes instead of plaintext\n")
	fmt.Fprintf(w, "  -x, --hide               Hide plaintext passwords from console output\n")
	fmt.Fprintf(w, "  -s, --stats              Show runtime and result summary after completion\n")
	fmt.Fprintf(w, "  -v, --verbose            Print each HIBP request to show exactly what is sent to the API\n")
	fmt.Fprintf(w, "  -c, --credits            Show credits\n")
	fmt.Fprintf(w, "  -h, --help               Show help\n")
}

func printCredits(w io.Writer) {
	fmt.Fprintf(w, "PwnedCheck - v%s\n\nby mohamedation\nReal work is done by Troy Hunt and the HIBP API.\n", version)
}
