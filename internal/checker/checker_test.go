package checker

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/mohamedation/PwnedCheck/internal/bitwarden"
)

type mockClient struct {
	results map[string]bool
	errs    map[string]error
	waits   int
}

func (m *mockClient) CheckPassword(password string, _ bool) (bool, error) {
	if err, ok := m.errs[password]; ok {
		return false, err
	}
	return m.results[password], nil
}

func (m *mockClient) Wait() { m.waits++ }

func TestRunInlineBadGoodHideStats(t *testing.T) {
	client := &mockClient{
		results: map[string]bool{"bad": true, "good": false},
		errs:    map[string]error{},
	}

	code := run(Config{
		Args:         []string{"bad", "good"},
		HidePassword: true,
		ShowStats:    true,
	}, client, nil, nil)
	if code != 0 {
		t.Fatalf("exit code = %d", code)
	}
	if client.waits != 2 {
		t.Fatalf("waits = %d, want 2", client.waits)
	}
}

func TestRunInlineShowsPasswordAndHandlesError(t *testing.T) {
	client := &mockClient{
		results: map[string]bool{"shown": false},
		errs:    map[string]error{"boom": errors.New("api down")},
	}

	code := run(Config{
		Args: []string{"shown", "boom"},
	}, client, nil, nil)
	if code != 0 {
		t.Fatalf("exit code = %d", code)
	}
}

func TestRunFilePaths(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "passwords.txt")
	content := "badpass\n\n goodpass \n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	client := &mockClient{
		results: map[string]bool{"badpass": true, "goodpass": false},
		errs:    map[string]error{},
	}

	code := run(Config{
		InputFile:    path,
		HidePassword: false,
		ShowStats:    true,
	}, client, nil, nil)
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}

	errClient := &mockClient{
		results: map[string]bool{},
		errs:    map[string]error{"badpass": errors.New("fail"), "goodpass": errors.New("fail")},
	}
	code = run(Config{InputFile: path}, errClient, nil, nil)
	if code != 0 {
		t.Fatalf("exit with errors = %d", code)
	}
}

func TestRunFileEmptyAndMissing(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty.txt")
	if err := os.WriteFile(empty, []byte("\n\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	code := run(Config{InputFile: empty}, &mockClient{}, nil, nil)
	if code != 0 {
		t.Fatalf("empty file exit = %d", code)
	}

	code = run(Config{InputFile: "passwords.txt"}, &mockClient{}, nil, nil)
	if code != 1 {
		t.Fatalf("missing default exit = %d, want 1", code)
	}

	code = run(Config{InputFile: filepath.Join(dir, "missing.list")}, &mockClient{}, nil, nil)
	if code != 1 {
		t.Fatalf("missing custom exit = %d, want 1", code)
	}
}

func TestRunBitwardenFlows(t *testing.T) {
	client := &mockClient{
		results: map[string]bool{"pwned": true, "safe": false},
		errs:    map[string]error{"errpw": errors.New("api")},
	}

	readOK := func() (string, error) { return "vault-pw", nil }
	readErr := func() (string, error) { return "", errors.New("tty") }

	extractOK := func(string, string) ([]bitwarden.VaultEntry, error) {
		return []bitwarden.VaultEntry{
			{AccountName: "A", Username: "u", Password: "pwned"},
			{AccountName: "B", Username: "", Password: "safe"},
			{AccountName: "C", Username: "c", Password: "errpw"},
		}, nil
	}
	extractEmpty := func(string, string) ([]bitwarden.VaultEntry, error) {
		return nil, nil
	}
	extractErr := func(string, string) ([]bitwarden.VaultEntry, error) {
		return nil, errors.New("decrypt failed")
	}

	if code := run(Config{Bitwarden: true, InputFile: "x", ShowStats: true}, client, readOK, extractOK); code != 0 {
		t.Fatalf("bw ok exit = %d", code)
	}
	if code := run(Config{Bitwarden: true, HidePassword: true}, client, readOK, extractOK); code != 0 {
		t.Fatalf("bw hide exit = %d", code)
	}
	if code := run(Config{Bitwarden: true}, client, readErr, extractOK); code != 1 {
		t.Fatalf("bw read err exit = %d", code)
	}
	if code := run(Config{Bitwarden: true}, client, readOK, extractErr); code != 1 {
		t.Fatalf("bw extract err exit = %d", code)
	}
	if code := run(Config{Bitwarden: true}, client, readOK, extractEmpty); code != 0 {
		t.Fatalf("bw empty exit = %d", code)
	}
}

func TestRunPublicEntryUsesHIBP(t *testing.T) {
	// Smoke: public Run builds a real client; with no args and missing default file it exits 1.
	// Avoid network by pointing at missing default passwords.txt from a temp cwd.
	dir := t.TempDir()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })

	code := Run(Config{InputFile: "passwords.txt"})
	if code != 1 {
		t.Fatalf("Run missing default = %d", code)
	}
}

func TestStatisticsSummary(t *testing.T) {
	s := &statistics{badPasswords: 1, goodPasswords: 2, totalChecked: 3}
	s.printSummary()
}
