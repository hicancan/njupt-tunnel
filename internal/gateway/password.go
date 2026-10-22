package gateway

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
)

// encryptPassword implements the gateway's AES-128-CBC wire format. Its IV is
// the reversed session key; PKCS7 padding always adds at least one byte.
func encryptPassword(password, sessionKey string) (string, error) {
	if len(sessionKey) != aes.BlockSize {
		return "", errors.New("session key must contain exactly 16 bytes")
	}
	var iv [aes.BlockSize]byte
	for i := range iv {
		iv[i] = sessionKey[len(iv)-1-i]
	}
	block, err := aes.NewCipher([]byte(sessionKey))
	if err != nil {
		return "", errors.New("cannot initialize password cipher")
	}
	padding := aes.BlockSize - len(password)%aes.BlockSize
	ciphertext := make([]byte, len(password)+padding)
	copy(ciphertext, password)
	for i := len(password); i < len(ciphertext); i++ {
		ciphertext[i] = byte(padding)
	}
	cipher.NewCBCEncrypter(block, iv[:]).CryptBlocks(ciphertext, ciphertext)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}
