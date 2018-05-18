package betchley

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"os"
)

func EncodePrivateKeyPEM(w io.Writer, key *rsa.PrivateKey) error {
	return pem.Encode(w, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
}

func SavePrivateKeyPEM(fileName string, key *rsa.PrivateKey) error {
	f, err := os.Create(fileName)
	if err != nil {
		return err
	}
	if err = EncodePrivateKeyPEM(f, key); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func EncodePublicKeyPEM(w io.Writer, key *rsa.PublicKey) error {
	b, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return err
	}
	return pem.Encode(w, &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: b,
	})
}

func SavePublicKeyPEM(fileName string, key *rsa.PublicKey) error {
	f, err := os.Create(fileName)
	if err != nil {
		return err
	}
	if err = EncodePublicKeyPEM(f, key); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func GenerateRSAKeyPair(bitSize int) (*rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		return nil, fmt.Errorf("could not generate %d bit RSA key: %v", bitSize, err)
	}
	return key, nil
}

func DecodePEMType(pemContents []byte, blockType string) ([]byte, error) {
	var skippedTypes []string
	var block *pem.Block

	for {
		block, pemContents = pem.Decode(pemContents)
		if block == nil {
			return nil, fmt.Errorf(
				"failed to find %s in PEM data after skipping types %v",
				blockType, skippedTypes)
		}
		if block.Type == blockType {
			return block.Bytes, nil
		} else {
			skippedTypes = append(skippedTypes, block.Type)
			continue
		}
	}
	panic("unreachable")
}

func DecodePrivateKeyPEM(pemContents []byte) (*rsa.PrivateKey, error) {
	b, err := DecodePEMType(pemContents, "RSA PRIVATE KEY")
	if err != nil {
		return nil, err
	}
	prvkey, err := x509.ParsePKCS1PrivateKey(b)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DER encoded private key: %v", err)
	}
	return prvkey, nil
}

func ReadPrivateKeyPEM(fileName string) (*rsa.PrivateKey, error) {
	pemContents, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, fmt.Errorf("could not read private key in %q: %v",
			fileName, err)
	}
	return DecodePrivateKeyPEM(pemContents)
}
