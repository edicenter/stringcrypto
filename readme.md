# STRINGCRYPTO

Command-line program that encrypts and decrypts text.

When encrypting, it takes plain text from stdin and writes the
encrypted string to stdout.

When decrypting, it takes the encrypted string from stdin and
writes the plain text to stdout.

Install `GO` and compile to `stringcrypto.exe`:

    go build -ldflags "-s"


Run `stringcrypto.exe` without arguments to see the usage info.

Read description in `main.go` for more details.

