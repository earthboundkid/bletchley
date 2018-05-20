package main

import (
	"crypto/rsa"
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/carlmjohnson/bletchley"
)

func main() {
	c := FromArgs(os.Args[1:])
	if err := c.Exec(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

type Config struct {
	KeySource    string
	CipherSource string
	MessageDest  string
}

func FromArgs(args []string) *Config {
	conf := &Config{}
	fl := flag.NewFlagSet("bletchley-decode", flag.ExitOnError)
	fl.StringVar(&conf.KeySource, "key-src", "private.pem", "private key to decode cipher with")
	fl.StringVar(&conf.CipherSource, "cipher-src", "cipher.pem", "file to decrypt")
	fl.StringVar(&conf.MessageDest, "msg-dest", "-", "file to save decrypted message into")
	fl.Usage = func() {
		fmt.Fprintf(os.Stderr,
			`bletchley-decode decodes a bletchley cipher PEM file.

Usage of bletchley-decode:

`,
		)
		fl.PrintDefaults()
	}
	_ = fl.Parse(args)

	return conf
}

func (config *Config) Exec() error {
	var (
		prv *rsa.PrivateKey
		err error
	)
	if config.KeySource == "" || config.KeySource == "-" {
		stdin, _ := ioutil.ReadAll(os.Stdin)
		prv, err = bletchley.DecodePrivateKeyPEM(stdin)
	} else {
		prv, err = bletchley.ReadPrivateKeyPEM(config.KeySource)
	}
	if err != nil {
		return err
	}
	var cipherpems []byte
	if config.CipherSource == "" || config.CipherSource == "-" {
		cipherpems, err = ioutil.ReadAll(os.Stdin)
	} else {
		cipherpems, err = ioutil.ReadFile(config.CipherSource)
	}

	f := os.Stdout
	if config.MessageDest != "" && config.MessageDest != "-" {
		f, err = os.Create(config.MessageDest)
		if err != nil {
			return fmt.Errorf("could not create %q: %v", config.MessageDest, err)
		}
	}
	return bletchley.DecodeMessagePEM(f, cipherpems, prv)
}
