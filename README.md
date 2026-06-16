<div align="center">

# PwnedCheck

**PwnedCheck is a command-line tool for checking whether passwords have appeared in known data breaches using the [Have I Been Pwned](https://haveibeenpwned.com/) API and supports encrypted Bitwarden vaults exports.**


[![Go Version](https://img.shields.io/badge/go-1.25-00ADD8?logo=go)](https://go.dev)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/mohamedation/PwnedCheck)](https://goreportcard.com/report/github.com/mohamedation/PwnedCheck)

</div>

<p align="center">
  <img src="assets/showcase-bitwarden.gif" alt="PwnedCheck Bitwarden Decryption Demo" width="750">
</p>

## Features

- Check single passwords from the command line
- Process passwords from a file
- Accept pre-hashed SHA-1 input with `-hashed`
- Check Bitwarden encrypted exports with `-bw`
- Hide plaintext passwords in output with `-hide`
- Show request-level HIBP diagnostics with `-v`
- Print end-of-run statistics with `-stats`

## Installation

### Prebuilt release

You can download a precompiled static binary tailored for your operating system directly from releases page:

1. Go to the [Releases Page](https://github.com/mohamedation/PwnedCheck/releases/latest).
2. Download the archive corresponding to your Platform and Architecture:
   * **Linux:** `pwnedcheck_x.x.x_linux_amd64.tar.gz` (or `arm64`)
   * **macOS:** `pwnedcheck_x.x.x_darwin_amd64.tar.gz` (or `arm64`)
   * **Windows:** `pwnedcheck_x.x.x_windows_amd64.zip`
3. Extract the archive payload to get the executable file.

#### Running the Executable

**Linux / macOS:**
Open your terminal inside the extracted directory, make the binary executable, and run it:
```bash
chmod +x pwnedcheck
./pwnedcheck -h
```

**Windows:**
untested, but feedback is apprecieated

Open PowerShell or Command Prompt inside the folder containing the extracted pwnedcheck.exe and execute:
```powershell
.\pwnedcheck.exe -h
```

### With Go

Install the CLI into your Go bin directory:

```bash
go install github.com/mohamedation/PwnedCheck/cmd/pwnedcheck@latest
```

### From source with Make

```bash
git clone https://github.com/mohamedation/PwnedCheck.git
cd PwnedCheck
make install
```

That installs the current host binary to your Go `bin` directory.

### Build platform-specific binaries

Use the Makefile to produce release binaries for Linux or macOS:

```bash
make build-linux
make build-macos
```

The binaries are written to `dist/` with your current Go architecture in the filename.

If you want the binary copied into your Go bin directory with an OS-specific name, use:

```bash
make install-linux
make install-macos
```

Those commands install as `pwnedcheck`.

## Usage

Run from source:

```bash
go run ./cmd/pwnedcheck -v god
```

Or run the installed binary:

```bash
pwnedcheck -i passwords.list -stats
```

### Common examples

Check a single password:

```bash
pwnedcheck password123
```

Check multiple passwords:

```bash
pwnedcheck love sex secret god
```
![Inline Password Check](assets/showcase-inline.gif)

Check passwords from a file:

```bash
pwnedcheck -i passwords.list
```

Check pre-hashed SHA-1 values:

```bash
pwnedcheck -hashed -i passwords.list
```
![Inline Password Check](assets/showcase-hide.gif)

Check a Bitwarden encrypted export:

```bash
pwnedcheck -bw -i bitwarden_encrypted_export.json -hide -stats
```

Enable verbose HIBP request logging:

```bash
pwnedcheck -v password123
```

## Options

- `-i, --input <string>` : Input file containing passwords or JSON export (default `"passwords.txt"`)
- `-bw, --bitwarden`     : Treat input file as a Bitwarden password-protected encrypted JSON export
- `-H, --hashed`         : Treat input as pre-computed SHA-1 hashes instead of plaintext
- `-x, --hide`           : Hide plaintext passwords from console output
- `-s, --stats`          : Show runtime and result summary after completion
- `-v, --verbose`        : Print each HIBP request and response status to show API diagnostics
- `-c, --credits`        : Show credits
- `-h, --help`           : Show help

## Security Model

PwnedCheck uses the k-anonymity approach used by HIBP:

- Only the first 5 characters of the SHA-1 hash are sent to the API
- The full password is never transmitted
- Bitwarden exports are decrypted locally in memory before checking

## Example Output

```text
[1/2] Checking...
BAD PASSWORD — BREACH DETECTED (item #1)
	Password: 123456

Total runtime: 1.5s
Total passwords checked: 2
Bad passwords found: 1
Good passwords: 1
```

## Repository Layout

- `cmd/pwnedcheck`: CLI entrypoint and flag parsing
- `internal/checker`: run loop and output formatting
- `internal/hibp`: HIBP client and password hashing
- `internal/bitwarden`: Bitwarden export decryption

## License

[GNU General Public License v3.0](LICENSE)