package ecies

import (
	"io"
)

type SymmetricCipherMode struct {
	Encryptor func(io.Reader, *ECIESParams, []byte, []byte, []byte) ([]byte, error)
	Decryptor func(io.Reader, *ECIESParams, []byte, []byte, []byte) ([]byte, error)
}

// Generate an initialisation vector for CTR mode.
func GenerateIV(length int, rand io.Reader) (iv []byte, err error) {
	iv = make([]byte, length)
	_, err = io.ReadFull(rand, iv)
	return
}

// SymmetricEncrypt encrypts the `plaintext` bytes with a symmetric cipher
// specified by `params` using key `key` and optionally authenticates
// the message with `authenticationData` (for AEAD ciphers (GCM) only)
func SymmetricEncrypt(rand io.Reader, params *ECIESParams, key, plaintext, authenticationData []byte) ([]byte, error) {
	return params.SymmetricCipherMode.Encryptor(rand, params, key, plaintext, authenticationData)
}

// SymmetricDecrypt decrypts the `ciphertext` bytes with a symmetric cipher
// specified by `params` using key `key` and optionally authenticates
// the message with `authenticationData` (for AEAD ciphers (GCM) only)
func SymmetricDecrypt(rand io.Reader, params *ECIESParams, key, ciphertext, authenticationData []byte) ([]byte, error) {
	return params.SymmetricCipherMode.Decryptor(rand, params, key, ciphertext, authenticationData)
}
