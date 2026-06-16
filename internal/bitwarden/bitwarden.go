package bitwarden

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
)

type BitwardenEncryptedExport struct {
	Encrypted         bool   `json:"encrypted"`
	PasswordProtected bool   `json:"passwordProtected"`
	Salt              string `json:"salt"`
	KdfIterations     int    `json:"kdfIterations"`
	KdfType           int    `json:"kdfType"`
	Data              string `json:"data"`
}

type BitwardenDecryptedSchema struct {
	Items []struct {
		Type  int    `json:"type"`
		Name  string `json:"name"`
		Login *struct {
			Username string `json:"username"`
			Password string `json:"password"`
		} `json:"login"`
	} `json:"items"`
}

// struct for fields we need
type VaultEntry struct {
	AccountName string
	Username    string
	Password    string
}

// extraction
func ExtractEntries(filePath string, exportPassword string) ([]VaultEntry, error) {
	fileBytes, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	var vault BitwardenEncryptedExport
	if err := json.Unmarshal(fileBytes, &vault); err != nil {
		return nil, fmt.Errorf("failed to parse encrypted JSON format: %w", err)
	}

	if !vault.Encrypted || !vault.PasswordProtected {
		return nil, errors.New("file is not a valid Bitwarden password-protected export. unprotected exports are not supported or encouraged.")
	}

	if vault.KdfType != 0 {
		return nil, fmt.Errorf("unsupported KDF type %d (only PBKDF2/kdfType=0 is supported)", vault.KdfType)
	}

	// i need more tests to make sure bitwarden vaults are compatible, so TO DO
	// PBKDF2-SHA256.
	saltBytes := []byte(vault.Salt)

	masterKey := pbkdf2.Key(
		[]byte(exportPassword),
		saltBytes,
		vault.KdfIterations,
		32,
		sha256.New,
	)

	hkdfEncReader := hkdf.Expand(sha256.New, masterKey, []byte("enc"))
	encKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdfEncReader, encKey); err != nil {
		return nil, err
	}

	hkdfMacReader := hkdf.Expand(sha256.New, masterKey, []byte("mac"))
	macKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdfMacReader, macKey); err != nil {
		return nil, err
	}

	rawData := vault.Data
	if idx := strings.Index(rawData, "."); idx != -1 {
		rawData = rawData[idx+1:]
	}

	parts := strings.Split(rawData, "|")
	if len(parts) < 3 {
		return nil, errors.New("invalid vault ciphertext layout")
	}

	ivBytes, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode IV: %w", err)
	}

	cipherBytes, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	macBytes, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("failed to decode MAC: %w", err)
	}

	h := hmac.New(sha256.New, macKey)
	h.Write(ivBytes)
	h.Write(cipherBytes)
	if !hmac.Equal(macBytes, h.Sum(nil)) {
		return nil, errors.New("HMAC verification failed — wrong password or corrupted file")
	}

	// AES-256-CBC
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}
	if len(cipherBytes)%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext length is not a multiple of block size")
	}

	plaintext := make([]byte, len(cipherBytes))
	cipher.NewCBCDecrypter(block, ivBytes).CryptBlocks(plaintext, cipherBytes)

	plaintext, err = pkcs7Unpad(plaintext, aes.BlockSize)
	if err != nil {
		return nil, fmt.Errorf("unpad error: %w", err)
	}

	var decryptedData BitwardenDecryptedSchema
	if err := json.Unmarshal(plaintext, &decryptedData); err != nil {
		return nil, fmt.Errorf("failed to parse decrypted vault: %w", err)
	}

	var entries []VaultEntry
	for _, item := range decryptedData.Items {
		if item.Type == 1 && item.Login != nil && item.Login.Password != "" {
			entries = append(entries, VaultEntry{
				AccountName: item.Name,
				Username:    item.Login.Username,
				Password:    item.Login.Password,
			})
		}
	}

	return entries, nil
}

func pkcs7Unpad(b []byte, blockSize int) ([]byte, error) {
	if len(b) == 0 {
		return nil, errors.New("input is empty")
	}
	if len(b)%blockSize != 0 {
		return nil, errors.New("invalid block size alignment")
	}
	c := b[len(b)-1]
	n := int(c)
	if n == 0 || n > blockSize {
		return nil, errors.New("invalid padding byte value")
	}
	for i := 0; i < n; i++ {
		if b[len(b)-n+i] != c {
			return nil, errors.New("padding bytes are inconsistent")
		}
	}
	return b[:len(b)-n], nil
}
