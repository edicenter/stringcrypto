package main

import (
	"flag"
	"fmt"
	"os"
	"stringcrypto"
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

	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}

	if len(*flagPassword) == 0 {
		flag.Usage()
		os.Exit(3)
	}

	if *flagEncrypt {
		encrypted := stringcrypto.Encrypt(flag.Arg(0), *flagPassword)
		fmt.Print(encrypted)
	} else if *flagDecrypt {
		decrypted, err := stringcrypto.Decrypt(flag.Arg(0), *flagPassword)
		if err != nil {
			fmt.Fprint(os.Stderr, err)
		}
		fmt.Print(decrypted)
	}

}
