package betchley

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
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

func NewRSAPrivateKey(bitSize int) *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		panic(fmt.Sprintf("could not generate %d bit RSA key: %v", bitSize, err))
	}
	return key
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

func DecodePublicKeyPEM(pemContents []byte) (*rsa.PublicKey, error) {
	b, err := DecodePEMType(pemContents, "PUBLIC KEY")
	if err != nil {
		return nil, err
	}

	pub, err := x509.ParsePKIXPublicKey(b)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DER encoded public key: %v", err)
	}
	if pub, ok := pub.(*rsa.PublicKey); ok {
		return pub, nil
	}
	return nil, fmt.Errorf("key is %T not *rsa.PublicKey", pub)
}

func ReadPublicKeyPEM(fileName string) (*rsa.PublicKey, error) {
	pemContents, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, fmt.Errorf("could not read public key in %q: %v",
			fileName, err)
	}
	return DecodePublicKeyPEM(pemContents)
}

// NewEncryptionKey generates a random 256-bit key for Encrypt() and
// Decrypt(). It panics if the source of randomness fails.
func NewEncryptionKey() *[32]byte {
	key := [32]byte{}
	_, err := io.ReadFull(rand.Reader, key[:])
	if err != nil {
		panic(err)
	}
	return &key
}

// Encrypt encrypts data using 256-bit AES-GCM.  This both hides the content of
// the data and provides a check that it hasn't been altered. Output takes the
// form nonce|ciphertext|tag where '|' indicates concatenation.
func Encrypt(plaintext []byte, key *[32]byte) (ciphertext []byte, err error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt decrypts data using 256-bit AES-GCM.  This both hides the content of
// the data and provides a check that it hasn't been altered. Expects input
// form nonce|ciphertext|tag where '|' indicates concatenation.
func Decrypt(ciphertext []byte, key *[32]byte) (plaintext []byte, err error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("malformed ciphertext")
	}

	return gcm.Open(nil,
		ciphertext[:gcm.NonceSize()],
		ciphertext[gcm.NonceSize():],
		nil,
	)
}

func EncodeMessage(plaintext []byte, pub *rsa.PublicKey) (otp *[32]byte, key, ciphertext []byte, err error) {
	otp = NewEncryptionKey()
	key, err = rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, otp[:], nil)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("encyption error: %v", err)
	}
	ciphertext, err = Encrypt(plaintext, otp)
	return
}

func EncodeMessagePEM(w io.Writer, plaintext []byte, pub *rsa.PublicKey) error {
	_, key, ciphertext, err := EncodeMessage(plaintext, pub)
	if err != nil {
		return err
	}
	err = pem.Encode(w, &pem.Block{
		Type:  "BETCHLEY KEY",
		Bytes: key,
	})
	if err != nil {
		return err
	}
	return pem.Encode(w, &pem.Block{
		Type:  "BETCHLEY CIPHERTEXT",
		Bytes: ciphertext,
	})
}
