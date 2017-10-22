package ecies

import (
	"io"
)

type SymmetricCipherMode struct {
	Encryptor func(io.Reader, *ECIESParams, []byte, []byte) ([]byte, error)
	Decryptor func(io.Reader, *ECIESParams, []byte, []byte) ([]byte, error)
}

// Generate an initialisation vector for CTR mode.
func GenerateIV(length int, rand io.Reader) (iv []byte, err error) {
	iv = make([]byte, length)
	_, err = io.ReadFull(rand, iv)
	return
}

func SymmetricEncrypt(rand io.Reader, params *ECIESParams, key []byte, plaintext []byte) ([]byte, error) {
	return params.SymmetricCipherMode.Encryptor(rand, params, key, plaintext)
}

func SymmetricDecrypt(rand io.Reader, params *ECIESParams, key []byte, ciphertext []byte) ([]byte, error) {
	return params.SymmetricCipherMode.Decryptor(rand, params, key, ciphertext)
}
