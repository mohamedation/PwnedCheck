package main

import (
	"bufio"
	"crypto/sha1"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorReset  = "\033[0m"
)

type Config struct {
	InputFile    string
	IsHashed     bool
	HidePassword bool
	ShowHelp     bool
	ShowCredits  bool
	ShowStats    bool
}

type Statistics struct {
	StartTime     time.Time
	BadPasswords  int
	GoodPasswords int
	TotalChecked  int
}

func (s *Statistics) PrintSummary() {
	duration := time.Since(s.StartTime)
	fmt.Printf("\nTotal runtime: %s\n", duration)
	fmt.Printf("Total passwords checked: %d\n", s.TotalChecked)
	fmt.Printf("%sBad passwords found: %d%s\n", colorRed, s.BadPasswords, colorReset)
	fmt.Printf("%sGood passwords: %d%s\n", colorGreen, s.GoodPasswords, colorReset)
}

type HIBPClient struct {
	client *http.Client
}

func NewHIBPClient() *HIBPClient {
	return &HIBPClient{
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

func (h *HIBPClient) CheckPassword(hashString string) bool {
	prefix := hashString[:5]
	url := fmt.Sprintf("https://api.pwnedpasswords.com/range/%s", prefix)

	resp, err := h.client.Get(url)
	if err != nil {
		fmt.Printf("%sError making API request: %v%s\n", colorRed, err, colorReset)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("%sAPI request failed with status: %s%s\n", colorRed, resp.Status, colorReset)
		return false
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("%sError reading API response: %v%s\n", colorRed, err, colorReset)
		return false
	}

	suffix := hashString[5:]
	lines := strings.Split(string(body), "\n")
	for _, line := range lines {
		parts := strings.Split(line, ":")
		if len(parts) == 2 && parts[0] == suffix {
			return true
		}
	}
	return false
}

func main() {
	// Flags
	inputFile := flag.String("i", "passwords.txt", "Input file containing passwords to check")
	help := flag.Bool("h", false, "Show help")
	credits := flag.Bool("c", false, "Show credits")
	hashed := flag.Bool("hashed", false, "Indicate that the input file or provided password is already hashed")
	hidePassword := flag.Bool("hide", false, "Hide passwords in output")
	showStats := flag.Bool("stats", false, "Show statistics after completion")

	// Parse flags
	flag.Parse()

	config := Config{
		InputFile:    *inputFile,
		IsHashed:     *hashed,
		HidePassword: *hidePassword,
		ShowHelp:     *help,
		ShowCredits:  *credits,
		ShowStats:    *showStats,
	}

	// Show help
	if config.ShowHelp {
		showHelp()
		return
	}

	// Show credits
	if config.ShowCredits {
		fmt.Println("PwnedCheck")
		fmt.Println("by Mohamed")
		fmt.Println("Real Work is done by Troy Hunt and the HIBP API and everyone else who contributed to it.")
		return
	}

	// Check arguments
	if flag.NArg() > 0 {
		stats := Statistics{StartTime: time.Now()}

		// Process each password argument
		for i, password := range flag.Args() {
			fmt.Printf("\nChecking password %d of %d:\n", i+1, flag.NArg())
			found := checkSinglePassword(password, config.IsHashed, config.HidePassword)
			if found {
				stats.BadPasswords++
			} else {
				stats.GoodPasswords++
			}
			stats.TotalChecked++
		}

		// Print statistics
		if config.ShowStats {
			stats.PrintSummary()
		}
		return
	}

	// Process the input file
	stats := Statistics{StartTime: time.Now()}

	file, err := os.Open(config.InputFile)
	if err != nil {
		if os.IsNotExist(err) && config.InputFile == "passwords.txt" {
			fmt.Printf("%sDefault passwords file not found%s\n\n", colorYellow, colorReset)
			showHelp()
			return
		}
		fmt.Printf("%sError opening file: %v%s\n", colorRed, err, colorReset)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNumber := 0

	client := NewHIBPClient()

	for scanner.Scan() {
		lineNumber++
		password := strings.TrimSpace(scanner.Text())
		if password == "" {
			continue
		}

		var hashString string
		if config.IsHashed {
			hashString = strings.ToUpper(password)
		} else {
			hash := sha1.Sum([]byte(password))
			hashString = strings.ToUpper(hex.EncodeToString(hash[:]))
		}

		// Check the password using the HIBP API
		found := client.CheckPassword(hashString)
		if found {
			fmt.Printf("%sBAD PASSWORD FOUND ON LINE: %d%s\n", colorRed, lineNumber, colorReset)
			if !config.HidePassword {
				fmt.Printf("Password: %s\n", password)
			}
			stats.BadPasswords++
		} else {
			stats.GoodPasswords++
		}
		stats.TotalChecked++
	}

	if err := scanner.Err(); err != nil {
		fmt.Printf("%sError reading file: %v%s\n", colorRed, err, colorReset)
	}

	// Print statistics
	if config.ShowStats {
		stats.PrintSummary()
	}
}

func checkSinglePassword(password string, hashed bool, hidePassword bool) bool {
	var hashString string
	if hashed {
		hashString = strings.ToUpper(password)
	} else {
		// Hash the password using SHA-1
		hash := sha1.Sum([]byte(password))
		hashString = strings.ToUpper(hex.EncodeToString(hash[:]))
	}

	client := NewHIBPClient()

	// Check the password using the HIBP API
	found := client.CheckPassword(hashString)
	if found {
		fmt.Printf("%sBAD PASSWORD FOUND%s\n", colorRed, colorReset)
		if !hidePassword {
			fmt.Printf("Password: %s\n", password)
		}
	} else {
		fmt.Printf("%sGood password%s\n", colorGreen, colorReset)
		if !hidePassword {
			fmt.Printf("Password: %s\n", password)
		}
	}
	return found
}

// Help
func showHelp() {
	fmt.Println("Usage: PwnedCheck [options] [password]")
	fmt.Println("Options:")
	fmt.Println("  -i string")
	fmt.Printf("        Input file containing passwords to check (default \"passwords.txt\")\n")
	fmt.Println("  -h    Show help")
	fmt.Println("  -c    Show credits")
	fmt.Println("  -hashed    Indicate that the input file or provided password is already hashed")
	fmt.Println("  -hide      Hide passwords in output")
	fmt.Println("  -stats     Show statistics after completion")
}
