# PwnedCheck

A command-line tool to check if passwords have been exposed in data breaches using the Have I Been Pwned (HIBP) API.

## Features

- Check single passwords from command line
- Process multiple passwords from a text file
- Support for pre-hashed passwords (SHA-1)
- Option to hide sensitive password data in output
- Colorized output for better visibility
- Optional statistics reporting for batch processing

## Installation

```bash
git clone https://github.com/mohamedation/PwnedCheck.git
cd PwnedCheck
go build
```

## Usage

### Check a single password:
```bash
./pwnedcheck password123
```

### Check multiple passwords:
```bash
./pwnedcheck love sex secret god
```

### Check passwords from a file:
```bash
./pwnedcheck -i passwords.txt
```

### Available Options:
- `-i string`: Input file containing passwords to check (default "passwords.txt")
- `-h`: Show help
- `-c`: Show credits
- `-hashed`: Indicate that the input file or provided password is already hashed
- `-hide`: Hide passwords in output
- `-stats`: Show statistics after completion

## Example Output

```
BAD PASSWORD FOUND ON LINE: 1
Password: 123456

Good password
Password: ComplexPassword123!

Total runtime: 1.5s
Total passwords checked: 2
Bad passwords found: 1
Good passwords: 1
```

## Security Note

This tool uses the k-Anonymity model implemented by HIBP API to check passwords securely:
- Only the first 5 characters of the password hash are sent to the API
- The actual password is never transmitted
- All processing is done locally on your machine

## Credits

- API Service: [Have I Been Pwned](https://haveibeenpwned.com/) by Troy Hunt
- The HIBP API and everyone who contributed to it

## License

[GNU General Public License v3.0](LICENSE)

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request