package main

import (
	"crypto/rsa"
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/carlmjohnson/betchley"
)

func main() {
	c := FromArgs(os.Args[1:])
	if err := c.Exec(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

type Config struct {
	KeySource     string
	MessageSource string
	CipherDest    string
}

func FromArgs(args []string) *Config {
	conf := &Config{}
	fl := flag.NewFlagSet("betchley-encode", flag.ExitOnError)
	fl.StringVar(&conf.KeySource, "key-src", "public.pem", "public key to encode message with")
	fl.StringVar(&conf.MessageSource, "msg-src", "-", "file to encrypt")
	fl.StringVar(&conf.CipherDest, "cipher-dest", "cipher.pem", "file to save encrypted ciphertext into")
	fl.Usage = func() {
		fmt.Fprintf(os.Stderr,
			`betchley-encode generates a one time use password and encodes it with a public
RSA key so that only the possessor of the private key can decode it, then
encodes the message with the one time use password.

Usage of betchley-encode:

`,
		)
		fl.PrintDefaults()
	}
	_ = fl.Parse(args)

	return conf
}

func (config *Config) Exec() error {
	var (
		pub *rsa.PublicKey
		err error
	)
	if config.KeySource == "" || config.KeySource == "-" {
		stdin, _ := ioutil.ReadAll(os.Stdin)
		pub, err = betchley.DecodePublicKeyPEM(stdin)
	} else {
		pub, err = betchley.ReadPublicKeyPEM(config.KeySource)
	}
	if err != nil {
		return err
	}
	var plaintext []byte
	if config.MessageSource == "" || config.MessageSource == "-" {
		plaintext, err = ioutil.ReadAll(os.Stdin)
	} else {
		plaintext, err = ioutil.ReadFile(config.MessageSource)
	}
	if err != nil {
		return fmt.Errorf("could not read message source: %v", err)
	}

	f := os.Stdout
	if config.CipherDest != "" && config.CipherDest != "-" {
		f, err = os.Create(config.CipherDest)
		if err != nil {
			return fmt.Errorf("could not create %q: %v", config.CipherDest, err)
		}
		defer f.Close()
	}

	return betchley.EncodeMessagePEM(f, plaintext, pub)
}
