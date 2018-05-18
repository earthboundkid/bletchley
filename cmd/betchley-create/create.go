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
	KeySource   string
	PrivateDest string
	PublicDest  string
	BitSize     int
}

func FromArgs(args []string) *Config {
	conf := &Config{}
	fl := flag.NewFlagSet("betchley-create", flag.ExitOnError)
	fl.StringVar(&conf.KeySource, "src", "", "private key to extract public key from")
	fl.StringVar(&conf.PrivateDest, "private-dest", "private.pem", "file to save private key to")
	fl.StringVar(&conf.PublicDest, "public-dest", "public.pem", "file to save public key to")
	fl.IntVar(&conf.BitSize, "bit-size", 4096, "bit size for RSA key")
	fl.Usage = func() {
		fmt.Fprintf(os.Stderr,
			`betchley-create generates a new public/private RSA key pair.

Use -src to extract the public component out of an existing private key PEM
file. In that case, -bit-size and -private-dest will be ignored.

Usage of betchley-create:

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
	if config.KeySource == "" {
		prv = betchley.NewRSAPrivateKey(config.BitSize)
		if config.PrivateDest == "" || config.PrivateDest == "-" {
			err = betchley.EncodePrivateKeyPEM(os.Stdout, prv)
		} else {
			err = betchley.SavePrivateKeyPEM(config.PrivateDest, prv)
		}
	} else if config.KeySource == "-" {
		stdin, _ := ioutil.ReadAll(os.Stdin)
		prv, err = betchley.DecodePrivateKeyPEM(stdin)
	} else {
		prv, err = betchley.ReadPrivateKeyPEM(config.KeySource)
	}
	if err != nil {
		return err
	}

	pub := &prv.PublicKey
	if config.PublicDest == "" || config.PublicDest == "-" {
		err = betchley.EncodePublicKeyPEM(os.Stdout, pub)
	} else {
		err = betchley.SavePublicKeyPEM(config.PrivateDest, pub)
	}
	return err
}
