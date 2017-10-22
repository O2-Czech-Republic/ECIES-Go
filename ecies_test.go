package ecies

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"testing"
)

// Test stream ciphers
func TestAESCFB(t *testing.T) {

	testParams := ECIESParams{
		Hash:                sha256.New,
		HashAlgo:            crypto.SHA256,
		Cipher:              aes.NewCipher,
		BlockSize:           aes.BlockSize,
		KeyLen:              16,
		SymmetricCipherMode: CFBCipherMode,
	}

	doTest(t, testParams)

}

func TestAESCTR(t *testing.T) {

	testParams := ECIESParams{
		Hash:                sha256.New,
		HashAlgo:            crypto.SHA256,
		Cipher:              aes.NewCipher,
		BlockSize:           aes.BlockSize,
		KeyLen:              16,
		SymmetricCipherMode: CTRCipherMode,
	}

	doTest(t, testParams)

}

// Test AEAD ciphers
func TestAESGCM(t *testing.T) {

	testParams := ECIESParams{
		Hash:                sha256.New,
		HashAlgo:            crypto.SHA256,
		Cipher:              aes.NewCipher,
		BlockSize:           aes.BlockSize,
		KeyLen:              16,
		SymmetricCipherMode: GCMCipherMode,
	}

	doTest(t, testParams)

}

func doTest(t *testing.T, params ECIESParams) {
	prv1, err := GenerateKey(rand.Reader, elliptic.P256(), &params)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}

	prv2, err := GenerateKey(rand.Reader, elliptic.P256(), &params)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}

	pub2 := prv2.PublicKey

	message := []byte("TestMessage")
	ciphertext, err := Encrypt(rand.Reader, &pub2, message, nil, nil)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}

	plaintext, err := prv2.Decrypt(rand.Reader, ciphertext, nil, nil)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}

	if !bytes.Equal(plaintext, message) {
		fmt.Println("ecies: plaintext doesn't match message")
		t.FailNow()
	}

	_, err = prv1.Decrypt(rand.Reader, ciphertext, nil, nil)
	if err == nil {
		fmt.Println("ecies: encryption should not have succeeded")
		t.FailNow()
	}
}
