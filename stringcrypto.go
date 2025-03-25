package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
)

const blockSize int = 16
const keySize int = 32
const nIteration int = 5000

func _PKCS7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func _PKCS7UnPadding(plantText []byte) []byte {
	length := len(plantText)
	unpadding := int(plantText[length-1])
	return plantText[:(length - unpadding)]
}

// Decrypt decrypts `ciphertext` encrypted with function `Encrypt` using the `password`.
// Returns plain text.
func Decrypt(ciphertext string, password string) (string, error) {
	cipherIV := strings.Split(ciphertext, "|")
	if len(cipherIV) != 2 {
		return "", fmt.Errorf("error: the given encrypted string must have two base64-encoded components separetated by a pipe: BASE64|BASE64")
	}
	cipherBytes, err := base64.StdEncoding.DecodeString(cipherIV[0])
	if err != nil {
		return "", fmt.Errorf("Error base64-decoding the first component of the encrypted string; %v", err)
	}
	iv, err := base64.StdEncoding.DecodeString(cipherIV[1])
	if err != nil {
		return "", fmt.Errorf("error base64-decoding the second component of the encrypted string; %v", err)
	}
	key, err := pbkdf2.Key(sha256.New, password, make([]byte, 0), nIteration, keySize)
	if err != nil {
		return "", fmt.Errorf("error making key from password; %v", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("error creating AES; %v", err)
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	plainBytes := make([]byte, len(cipherBytes))
	mode.CryptBlocks(plainBytes, cipherBytes)
	plainBytes = _PKCS7UnPadding(plainBytes)
	return string(plainBytes[:]), nil
}

// Encrypt encrypts text `plaintext` using the `password`
func Encrypt(plaintext string, password string) (string, error) {
	key, err := pbkdf2.Key(sha256.New, password, make([]byte, 0), nIteration, keySize)
	if err != nil {
		return "", fmt.Errorf("error making key from password; %v", err)
	}
	bIV := make([]byte, blockSize)
	rand.Read(bIV)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("error creating AES; %v", err)
	}
	mode := cipher.NewCBCEncrypter(block, bIV)
	padded := _PKCS7Padding([]byte(plaintext), blockSize)
	ciphertext := make([]byte, len(padded))
	mode.CryptBlocks(ciphertext, padded)
	return base64.StdEncoding.EncodeToString(ciphertext) + "|" + base64.StdEncoding.EncodeToString(bIV), nil
}
