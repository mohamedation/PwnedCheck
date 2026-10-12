package main

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseArgsDefaultsAndFlags(t *testing.T) {
	var errBuf bytes.Buffer
	cfg, credits, err := parseArgs(nil, &errBuf)
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	if credits {
		t.Fatal("credits should be false by default")
	}
	if cfg.InputFile != "passwords.txt" {
		t.Fatalf("InputFile = %q", cfg.InputFile)
	}
	if cfg.IsHashed || cfg.HidePassword || cfg.ShowStats || cfg.Bitwarden || cfg.Verbose {
		t.Fatalf("unexpected bool defaults: %+v", cfg)
	}
	if len(cfg.Args) != 0 {
		t.Fatalf("Args = %v", cfg.Args)
	}

	cfg, credits, err = parseArgs([]string{
		"-i", "vault.json",
		"--hashed",
		"-x",
		"-s",
		"--bitwarden",
		"--verbose",
		"--credits",
		"one", "two",
	}, &errBuf)
	if err != nil {
		t.Fatalf("parseArgs flags: %v", err)
	}
	if !credits {
		t.Fatal("expected credits")
	}
	if cfg.InputFile != "vault.json" {
		t.Fatalf("InputFile = %q", cfg.InputFile)
	}
	if !cfg.IsHashed || !cfg.HidePassword || !cfg.ShowStats || !cfg.Bitwarden || !cfg.Verbose {
		t.Fatalf("expected all bools true: %+v", cfg)
	}
	if len(cfg.Args) != 2 || cfg.Args[0] != "one" || cfg.Args[1] != "two" {
		t.Fatalf("Args = %v", cfg.Args)
	}
}

func TestParseArgsShortAliases(t *testing.T) {
	var errBuf bytes.Buffer
	cfg, credits, err := parseArgs([]string{"-H", "-bw", "-c", "-input", "list.txt"}, &errBuf)
	if err != nil {
		t.Fatal(err)
	}
	if !credits || !cfg.IsHashed || !cfg.Bitwarden || cfg.InputFile != "list.txt" {
		t.Fatalf("aliases not applied: credits=%v cfg=%+v", credits, cfg)
	}
}

func TestParseArgsHelpAndUnknown(t *testing.T) {
	var errBuf bytes.Buffer
	_, _, err := parseArgs([]string{"-h"}, &errBuf)
	if err != flag.ErrHelp {
		t.Fatalf("want ErrHelp, got %v", err)
	}

	errBuf.Reset()
	_, _, err = parseArgs([]string{"--not-a-real-flag"}, &errBuf)
	if err == nil || err == flag.ErrHelp {
		t.Fatalf("want parse error, got %v", err)
	}
	if errBuf.Len() == 0 {
		t.Fatal("expected flag package error output")
	}
}

func TestPrintUsageAndCredits(t *testing.T) {
	var buf bytes.Buffer
	printUsage(&buf)
	out := buf.String()
	for _, want := range []string{"PwnedCheck", "Usage:", "-bw", "-h, --help", version} {
		if !strings.Contains(out, want) {
			t.Fatalf("usage missing %q\n%s", want, out)
		}
	}

	buf.Reset()
	printCredits(&buf)
	out = buf.String()
	if !strings.Contains(out, "Troy Hunt") || !strings.Contains(out, version) {
		t.Fatalf("credits output: %s", out)
	}
}

func TestRunHelpCreditsAndErrors(t *testing.T) {
	var stdout, stderr bytes.Buffer

	if code := run([]string{"-h"}, &stdout, &stderr); code != 0 {
		t.Fatalf("help exit = %d", code)
	}
	if !strings.Contains(stderr.String(), "Usage:") {
		t.Fatalf("help should print usage to stderr: %s", stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"-c"}, &stdout, &stderr); code != 0 {
		t.Fatalf("credits exit = %d", code)
	}
	if !strings.Contains(stdout.String(), "Troy Hunt") {
		t.Fatalf("credits stdout: %s", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"--bogus"}, &stdout, &stderr); code != 2 {
		t.Fatalf("unknown flag exit = %d, want 2", code)
	}
}

func TestRunMissingDefaultFile(t *testing.T) {
	dir := t.TempDir()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })

	var stdout, stderr bytes.Buffer
	code := run(nil, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("missing passwords.txt exit = %d, want 1", code)
	}
}

func TestRunEmptyInputFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.txt")
	if err := os.WriteFile(path, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{"-i", path}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("empty file exit = %d", code)
	}
}
