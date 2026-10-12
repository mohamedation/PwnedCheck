package bitwarden

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
)

func TestPKCS7Unpad(t *testing.T) {
	tests := []struct {
		name    string
		in      []byte
		want    []byte
		wantErr bool
	}{
		{name: "valid", in: append([]byte("hello world!!!!"), 0x01), want: []byte("hello world!!!!")},
		{name: "empty", in: nil, wantErr: true},
		{name: "misaligned", in: []byte("123"), wantErr: true},
		{name: "zero pad", in: []byte("123456789012345\x00"), wantErr: true},
		{name: "pad too large", in: append(bytes.Repeat([]byte{1}, 15), 17), wantErr: true},
		{name: "inconsistent", in: append([]byte("hello world!!!"), 0x01, 0x02), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := pkcs7Unpad(tt.in, aes.BlockSize)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Fatalf("got %q want %q", got, tt.want)
			}
		})
	}
}

func TestExtractEntriesValidationErrors(t *testing.T) {
	dir := t.TempDir()

	missing := filepath.Join(dir, "nope.json")
	if _, err := ExtractEntries(missing, "pw"); err == nil {
		t.Fatal("expected missing file error")
	}

	badJSON := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(badJSON, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ExtractEntries(badJSON, "pw"); err == nil {
		t.Fatal("expected JSON error")
	}

	notProtected := filepath.Join(dir, "open.json")
	if err := os.WriteFile(notProtected, mustJSON(t, BitwardenEncryptedExport{
		Encrypted: true, PasswordProtected: false,
	}), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ExtractEntries(notProtected, "pw"); err == nil {
		t.Fatal("expected unprotected error")
	}

	badKDF := filepath.Join(dir, "kdf.json")
	if err := os.WriteFile(badKDF, mustJSON(t, BitwardenEncryptedExport{
		Encrypted: true, PasswordProtected: true, KdfType: 2, Salt: "s", KdfIterations: 1, Data: "x",
	}), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ExtractEntries(badKDF, "pw"); err == nil {
		t.Fatal("expected kdf error")
	}

	badLayout := filepath.Join(dir, "layout.json")
	if err := os.WriteFile(badLayout, mustJSON(t, BitwardenEncryptedExport{
		Encrypted: true, PasswordProtected: true, KdfType: 0, Salt: "salt", KdfIterations: 1000, Data: "2.only|two",
	}), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ExtractEntries(badLayout, "pw"); err == nil {
		t.Fatal("expected layout error")
	}

	badIV := filepath.Join(dir, "iv.json")
	if err := os.WriteFile(badIV, mustJSON(t, BitwardenEncryptedExport{
		Encrypted: true, PasswordProtected: true, KdfType: 0, Salt: "salt", KdfIterations: 1000,
		Data: "2.%%%|YWFh|YWFh",
	}), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ExtractEntries(badIV, "pw"); err == nil {
		t.Fatal("expected IV decode error")
	}
}

func TestExtractEntriesRoundTrip(t *testing.T) {
	password := "test-vault-password"
	salt := "unit-test-salt"
	iterations := 1000

	vaultJSON := []byte(`{
		"items": [
			{"type": 1, "name": "GitHub", "login": {"username": "me", "password": "secret1"}},
			{"type": 1, "name": "Empty", "login": {"username": "x", "password": ""}},
			{"type": 2, "name": "Note", "login": null},
			{"type": 1, "name": "NoLogin"}
		]
	}`)

	data := encryptVaultPayload(t, password, salt, iterations, vaultJSON)
	path := filepath.Join(t.TempDir(), "vault.json")
	export := BitwardenEncryptedExport{
		Encrypted:         true,
		PasswordProtected: true,
		Salt:              salt,
		KdfIterations:     iterations,
		KdfType:           0,
		Data:              "2." + data,
	}
	if err := os.WriteFile(path, mustJSON(t, export), 0o600); err != nil {
		t.Fatal(err)
	}

	entries, err := ExtractEntries(path, password)
	if err != nil {
		t.Fatalf("ExtractEntries: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries = %#v, want 1 login", entries)
	}
	if entries[0].AccountName != "GitHub" || entries[0].Username != "me" || entries[0].Password != "secret1" {
		t.Fatalf("unexpected entry: %#v", entries[0])
	}

	if _, err := ExtractEntries(path, "wrong-password"); err == nil {
		t.Fatal("expected HMAC failure for wrong password")
	}
}

func TestExtractEntriesDecodeErrors(t *testing.T) {
	password := "pw"
	salt := "salt"
	iterations := 500
	encKey, macKey := deriveKeys(t, password, salt, iterations)

	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		t.Fatal(err)
	}
	cipherBytes := bytes.Repeat([]byte{1}, aes.BlockSize)
	mac := hmacSHA256(macKey, iv, cipherBytes)

	dir := t.TempDir()

	// Bad ciphertext base64
	p1 := filepath.Join(dir, "ct.json")
	writeExport(t, p1, salt, iterations, "2."+b64(iv)+"|"+"%%%"+"|"+b64(mac))
	if _, err := ExtractEntries(p1, password); err == nil {
		t.Fatal("expected ciphertext decode error")
	}

	// Bad MAC base64
	p2 := filepath.Join(dir, "mac.json")
	writeExport(t, p2, salt, iterations, "2."+b64(iv)+"|"+b64(cipherBytes)+"|"+"%%%")
	if _, err := ExtractEntries(p2, password); err == nil {
		t.Fatal("expected MAC decode error")
	}

	// Ciphertext not multiple of block size (valid MAC over truncated payload)
	shortCT := cipherBytes[:15]
	shortMAC := hmacSHA256(macKey, iv, shortCT)
	p3 := filepath.Join(dir, "block.json")
	writeExport(t, p3, salt, iterations, "2."+b64(iv)+"|"+b64(shortCT)+"|"+b64(shortMAC))
	if _, err := ExtractEntries(p3, password); err == nil {
		t.Fatal("expected block size error")
	}

	// Valid crypto but invalid padding / JSON
	badPadPlain := bytes.Repeat([]byte{0x10}, aes.BlockSize) // invalid PKCS7 (all 0x10 but last should be pad count matching)
	// Use ciphertext that decrypts to inconsistent padding: encrypt zeros with wrong intent —
	// encrypt a full block of 0x00 which unpad will reject (pad byte 0).
	zeroPlain := make([]byte, aes.BlockSize)
	block, err := aes.NewCipher(encKey)
	if err != nil {
		t.Fatal(err)
	}
	ct := make([]byte, len(zeroPlain))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, zeroPlain)
	mac2 := hmacSHA256(macKey, iv, ct)
	p4 := filepath.Join(dir, "pad.json")
	writeExport(t, p4, salt, iterations, b64(iv)+"|"+b64(ct)+"|"+b64(mac2))
	if _, err := ExtractEntries(p4, password); err == nil {
		t.Fatal("expected unpad error")
	}

	_ = badPadPlain
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func writeExport(t *testing.T, path, salt string, iterations int, data string) {
	t.Helper()
	export := BitwardenEncryptedExport{
		Encrypted: true, PasswordProtected: true, Salt: salt, KdfIterations: iterations, KdfType: 0, Data: data,
	}
	if err := os.WriteFile(path, mustJSON(t, export), 0o600); err != nil {
		t.Fatal(err)
	}
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func deriveKeys(t *testing.T, password, salt string, iterations int) (encKey, macKey []byte) {
	t.Helper()
	masterKey := pbkdf2.Key([]byte(password), []byte(salt), iterations, 32, sha256.New)
	encKey = make([]byte, 32)
	macKey = make([]byte, 32)
	if _, err := io.ReadFull(hkdf.Expand(sha256.New, masterKey, []byte("enc")), encKey); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(hkdf.Expand(sha256.New, masterKey, []byte("mac")), macKey); err != nil {
		t.Fatal(err)
	}
	return encKey, macKey
}

func hmacSHA256(key, iv, ct []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(iv)
	h.Write(ct)
	return h.Sum(nil)
}

func pkcs7Pad(b []byte, blockSize int) []byte {
	n := blockSize - (len(b) % blockSize)
	return append(append([]byte{}, b...), bytes.Repeat([]byte{byte(n)}, n)...)
}

func encryptVaultPayload(t *testing.T, password, salt string, iterations int, plaintext []byte) string {
	t.Helper()
	encKey, macKey := deriveKeys(t, password, salt, iterations)

	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		t.Fatal(err)
	}

	padded := pkcs7Pad(plaintext, aes.BlockSize)
	block, err := aes.NewCipher(encKey)
	if err != nil {
		t.Fatal(err)
	}
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)
	mac := hmacSHA256(macKey, iv, ct)
	return b64(iv) + "|" + b64(ct) + "|" + b64(mac)
}
