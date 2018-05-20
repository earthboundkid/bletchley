# bletchley
Simple command line application for basic public key crypto


## Installation

First install [Go](http://golang.org).

If you just want to install the binary to your current directory and don't care about the source code, run

```bash
GOBIN="$(pwd)" GOPATH="$(mktemp -d)" go get github.com/carlmjohnson/bletchley/...
```


## Screenshots
```bash
$ bletchley-create -h
bletchley-create generates a new public/private RSA key pair.

Use -src to extract the public component out of an existing private key PEM
file. In that case, -bit-size and -private-dest will be ignored.

Usage of bletchley-create:

  -bit-size int
        bit size for RSA key (default 4096)
  -private-dest string
        file to save private key to (default "private.pem")
  -public-dest string
        file to save public key to (default "public.pem")
  -src string
        private key to extract public key from

$ bletchley-encode -h
bletchley-encode generates a one time use password and encodes it with a public
RSA key so that only the possessor of the private key can decode it, then
encodes the message with the one time use password.

Usage of bletchley-encode:

  -cipher-dest string
        file to save encrypted ciphertext into (default "cipher.pem")
  -key-src string
        public key to encode message with (default "public.pem")
  -msg-src string
        file to encrypt (default "-")

$ bletchley-decode -h
bletchley-decode decodes a bletchley cipher PEM file.

Usage of bletchley-decode:

  -cipher-src string
        file to decrypt (default "cipher.pem")
  -key-src string
        private key to decode cipher with (default "private.pem")
  -msg-dest string
        file to save decrypted message into (default "-")
```
