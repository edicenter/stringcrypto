/*
Encrypts or decrypts text from the `stdin`.

The encrypted string has two components, separetated by a pipe.
Both components are base64-encoded.

EXAMPLE ENCRYPTING

	> stringcrypto.exe  -e -p="123" "Möhren zu essen ist gesund."

	> D5k3Qw8R2R3GDnHITuy1SK4dZ1PTLmV/TZy5G5rKGsE=|V26jhnN1xZ2Wpde9SFNRmA==

EXAMPLE DECRYPTING

	> stringcrypto.exe  -d -p="123" "D5k3Qw8R2R3GDnHITuy1SK4dZ1PTLmV/TZy5G5rKGsE=|V26jhnN1xZ2Wpde9SFNRmA=="

	> Möhren zu essen ist gesund.
*/
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
)

var flagEncrypt = flag.Bool("e", false, "Encrypt base64 encoded string")
var flagDecrypt = flag.Bool("d", false, "Decrypt base64 encoded string")
var flagPassword = flag.String("p", "", "Password for encryption or decryption")

func main() {

	flag.Parse()

	if flag.NFlag() != 2 {
		flag.Usage()
		os.Exit(1)
	}

	if len(*flagPassword) == 0 {
		flag.Usage()
		os.Exit(2)
	}
	var payload string

	if flag.NArg() == 1 {
		payload = flag.Arg(0)
	} else {
		stdinBytes, err := io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprint(os.Stderr, err)
			os.Exit(3)
		}
		payload = string(stdinBytes)
	}

	if *flagEncrypt {
		encrypted, err := Encrypt(payload, *flagPassword)
		if err != nil {
			fmt.Fprint(os.Stderr, err)
			os.Exit(4)
		}
		fmt.Print(encrypted)
	} else if *flagDecrypt {
		decrypted, err := Decrypt(payload, *flagPassword)
		if err != nil {
			fmt.Fprint(os.Stderr, err)
			os.Exit(5)
		}
		fmt.Print(decrypted)
	}

}
