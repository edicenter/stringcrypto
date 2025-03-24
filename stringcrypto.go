/*
Encrypts or decrypts text from the command line.

The encrypted string has two components, separetated by a pipe.
Both components are base64-encoded.

EXAMPLE ENCRYPTING

	> stringcrypto.exe  -e -p="123" "Möhren zu essen ist gesund."

	> D5k3Qw8R2R3GDnHITuy1SK4dZ1PTLmV/TZy5G5rKGsE=|V26jhnN1xZ2Wpde9SFNRmA==

EXAMPLE DECRYPTING

	> stringcrypto.exe  -d -p="123" "D5k3Qw8R2R3GDnHITuy1SK4dZ1PTLmV/TZy5G5rKGsE=|V26jhnN1xZ2Wpde9SFNRmA=="

	> Möhren zu essen ist gesund.
*/
package stringcrypto

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
	cipher_bytes, _ := base64.StdEncoding.DecodeString(cipher_iv[0])
	iv, _ := base64.StdEncoding.DecodeString(cipher_iv[1])
	key, _ := pbkdf2.Key(sha256.New, password, make([]byte, 0), NUMITERATIONS, KEYSIZE)
	block, _ := aes.NewCipher(key)
	mode := cipher.NewCBCDecrypter(block, iv)
	plain_bytes := make([]byte, len(cipher_bytes))
	mode.CryptBlocks(plain_bytes, cipher_bytes)
	plain_bytes = PKCS7UnPadding(plain_bytes)
	return string(plain_bytes[:]), nil
}

func Encrypt(plaintext string, password string) string {
	key, _ := pbkdf2.Key(sha256.New, password, make([]byte, 0), NUMITERATIONS, KEYSIZE)
	bIV := make([]byte, BLOCKSIZE)
	rand.Read(bIV)
	block, _ := aes.NewCipher(key)
	mode := cipher.NewCBCEncrypter(block, bIV)
	padded := PKCS7Padding([]byte(plaintext), BLOCKSIZE)
	ciphertext := make([]byte, len(padded))
	mode.CryptBlocks(ciphertext, padded)
	return base64.StdEncoding.EncodeToString(ciphertext) + "|" + base64.StdEncoding.EncodeToString(bIV)
}
