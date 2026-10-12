package checker

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/mohamedation/PwnedCheck/internal/bitwarden"
	"github.com/mohamedation/PwnedCheck/internal/hibp"
	"golang.org/x/term"
)

const (
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorReset  = "\033[0m"
)

// Config holds runtime options for a PwnedCheck run.
type Config struct {
	InputFile    string
	IsHashed     bool
	HidePassword bool
	ShowStats    bool
	Bitwarden    bool
	Verbose      bool
	Args         []string
}

// passwordChecker is the HIBP API surface used by the checker.
type passwordChecker interface {
	CheckPassword(password string, alreadyHashed bool) (bool, error)
	Wait()
}

type vaultExtractor func(filePath, exportPassword string) ([]bitwarden.VaultEntry, error)
type passwordReader func() (string, error)

type statistics struct {
	startTime     time.Time
	badPasswords  int
	goodPasswords int
	totalChecked  int
}

func (s *statistics) printSummary() {
	fmt.Printf("\nTotal runtime: %s\n", time.Since(s.startTime))
	fmt.Printf("Total passwords checked: %d\n", s.totalChecked)
	fmt.Printf("%sBad passwords found: %d%s\n", colorRed, s.badPasswords, colorReset)
	fmt.Printf("%sGood passwords: %d%s\n", colorGreen, s.goodPasswords, colorReset)
}

// Run checks passwords according to cfg and returns a process exit code.
func Run(cfg Config) int {
	return run(cfg, hibp.NewClient(cfg.Verbose), defaultReadPassword, bitwarden.ExtractEntries)
}

func run(cfg Config, client passwordChecker, readPassword passwordReader, extract vaultExtractor) int {
	stats := &statistics{startTime: time.Now()}

	if len(cfg.Args) > 0 {
		return runInline(client, cfg, stats)
	}

	if cfg.Bitwarden {
		return runBitwarden(client, cfg, stats, readPassword, extract)
	}

	return runFile(client, cfg, stats)
}

func defaultReadPassword() (string, error) {
	fmt.Print("Enter Bitwarden Export Encryption Password: ")
	passwordBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(passwordBytes)), nil
}

func runInline(client passwordChecker, cfg Config, stats *statistics) int {
	total := len(cfg.Args)
	for i, password := range cfg.Args {
		fmt.Printf("\nChecking password %d of %d...\n", i+1, total)

		found, err := client.CheckPassword(password, cfg.IsHashed)
		if err != nil {
			fmt.Printf("%sError: %v%s\n", colorRed, err, colorReset)
		} else if found {
			fmt.Printf("%sBAD PASSWORD FOUND%s\n", colorRed, colorReset)
			if !cfg.HidePassword {
				fmt.Printf("  Password: %s\n", password)
			}
			stats.badPasswords++
		} else {
			fmt.Printf("%sGood password%s\n", colorGreen, colorReset)
			if !cfg.HidePassword {
				fmt.Printf("  Password: %s\n", password)
			}
			stats.goodPasswords++
		}
		stats.totalChecked++
		client.Wait()
	}

	if cfg.ShowStats {
		stats.printSummary()
	}
	return 0
}

func runBitwarden(client passwordChecker, cfg Config, stats *statistics, readPassword passwordReader, extract vaultExtractor) int {
	vaultPassword, err := readPassword()
	if err != nil {
		fmt.Printf("%sFailed to read password: %v%s\n", colorRed, err, colorReset)
		return 1
	}

	fmt.Println("Decrypting vault file in-memory...")
	entries, err := extract(cfg.InputFile, vaultPassword)
	if err != nil {
		fmt.Printf("%sBitwarden decryption error: %v%s\n", colorRed, err, colorReset)
		return 1
	}

	total := len(entries)
	if total == 0 {
		fmt.Printf("%sNo login entries found in vault.%s\n", colorYellow, colorReset)
		return 0
	}
	fmt.Printf("Found %d login entries in vault.\n\n", total)

	for i, entry := range entries {
		fmt.Printf("[%d/%d] Checking %s...\r", i+1, total, entry.AccountName)

		found, err := client.CheckPassword(entry.Password, false)
		if err != nil {
			fmt.Printf("%sError checking %s: %v%s\n", colorRed, entry.AccountName, err, colorReset)
			stats.totalChecked++
			client.Wait()
			continue
		}

		if found {
			fmt.Printf("\r\033[K%sBAD PASSWORD — BREACH DETECTED%s\n", colorRed, colorReset)
			fmt.Printf("  Account:  %s\n", entry.AccountName)
			if entry.Username != "" {
				fmt.Printf("  Username: %s\n", entry.Username)
			}
			if !cfg.HidePassword {
				fmt.Printf("  Password: %s\n", entry.Password)
			}
			stats.badPasswords++
		} else {
			stats.goodPasswords++
		}
		stats.totalChecked++
		client.Wait()
	}

	fmt.Print("\r\033[K")

	if cfg.ShowStats {
		stats.printSummary()
	}
	return 0
}

func runFile(client passwordChecker, cfg Config, stats *statistics) int {
	file, err := os.Open(cfg.InputFile)
	if err != nil {
		if os.IsNotExist(err) && cfg.InputFile == "passwords.txt" {
			fmt.Printf("%sDefault passwords file not found.%s\n", colorYellow, colorReset)
			return 1
		}
		fmt.Printf("%sError opening file: %v%s\n", colorRed, err, colorReset)
		return 1
	}
	defer file.Close()

	var passwords []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if line := strings.TrimSpace(scanner.Text()); line != "" {
			passwords = append(passwords, line)
		}
	}

	total := len(passwords)
	if total == 0 {
		fmt.Printf("%sNo passwords to check.%s\n", colorYellow, colorReset)
		return 0
	}

	for i, password := range passwords {
		fmt.Printf("[%d/%d] Checking...\r", i+1, total)

		found, err := client.CheckPassword(password, cfg.IsHashed)
		if err != nil {
			fmt.Printf("%sError (item #%d): %v%s\n", colorRed, i+1, err, colorReset)
			stats.totalChecked++
			client.Wait()
			continue
		}

		if found {
			fmt.Printf("%sBAD PASSWORD — BREACH DETECTED (item #%d)%s\n", colorRed, i+1, colorReset)
			if !cfg.HidePassword {
				fmt.Printf("  Password: %s\n", password)
			}
			stats.badPasswords++
		} else {
			stats.goodPasswords++
		}
		stats.totalChecked++
		client.Wait()
	}

	fmt.Print("\r\033[K")

	if cfg.ShowStats {
		stats.printSummary()
	}
	return 0
}
