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

const BLOCKSIZE int = 16
const KEYSIZE int = 32
const NUMITERATIONS int = 5000

func PKCS7Padding(ciphertext []byte, block_size int) []byte {
	padding := block_size - len(ciphertext)%block_size
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS7UnPadding(plantText []byte) []byte {
	length := len(plantText)
	unpadding := int(plantText[length-1])
	return plantText[:(length - unpadding)]
}

func Decrypt(ciphertext string, password string) (string, error) {
	cipher_iv := strings.Split(ciphertext, "|")
	if len(cipher_iv) != 2 {
		return "", fmt.Errorf("error: the given encrypted string must have two base64-encoded components separetated by a pipe: BASE64|BASE64")
	}
	cipher_bytes, err := base64.StdEncoding.DecodeString(cipher_iv[0])
	if err != nil {
		return "", fmt.Errorf("error base64-decoding the first component of the encrypted string; %v", err)
	}
	iv, err := base64.StdEncoding.DecodeString(cipher_iv[1])
	if err != nil {
		return "", fmt.Errorf("error base64-decoding the second component of the encrypted string; %v", err)
	}
	key, err := pbkdf2.Key(sha256.New, password, make([]byte, 0), NUMITERATIONS, KEYSIZE)
	if err != nil {
		return "", fmt.Errorf("error making key from password; %v", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("error creating AES; %v", err)
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	plain_bytes := make([]byte, len(cipher_bytes))
	mode.CryptBlocks(plain_bytes, cipher_bytes)
	plain_bytes = PKCS7UnPadding(plain_bytes)
	return string(plain_bytes[:]), nil
}

func Encrypt(plaintext string, password string) (string, error) {
	key, err := pbkdf2.Key(sha256.New, password, make([]byte, 0), NUMITERATIONS, KEYSIZE)
	if err != nil {
		return "", fmt.Errorf("error making key from password; %v", err)
	}
	bIV := make([]byte, BLOCKSIZE)
	rand.Read(bIV)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("error creating AES; %v", err)
	}
	mode := cipher.NewCBCEncrypter(block, bIV)
	padded := PKCS7Padding([]byte(plaintext), BLOCKSIZE)
	ciphertext := make([]byte, len(padded))
	mode.CryptBlocks(ciphertext, padded)
	return base64.StdEncoding.EncodeToString(ciphertext) + "|" + base64.StdEncoding.EncodeToString(bIV), nil
}
