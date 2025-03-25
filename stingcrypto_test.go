package main

import "testing"

func TestEncryptDecrypt(t *testing.T) {
	password := "123"
	expected := "hello world"
	encrypted, err := Encrypt(expected, password)
	if err != nil {
		t.Errorf("Error ecnrypting: %v", err)
	}

	decrypted, err := Decrypt(encrypted, password)

	if err != nil {
		t.Errorf("Error decrypting: %v", err)
	}

	if expected != decrypted {
		t.Errorf("Expected %s, got %s instead", expected, decrypted)
	}
}
