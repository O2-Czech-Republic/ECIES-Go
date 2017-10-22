package ecies

import (
	"crypto/cipher"
	"io"
)

var CBCCipherMode = SymmetricCipherMode{
	Encryptor: CBCEncrypt,
	Decryptor: CBCDecrypt,
}

// CBCEncrypt performs Cipher Block Chaining (CBC) encryption using the block cipher specified in
// the parameters
func CBCEncrypt(rand io.Reader, params *ECIESParams, key, plaintext []byte) ([]byte, error) {

	blockCipher, err := params.Cipher(key)
	if err != nil {
		return nil, err
	}

	iv, err := GenerateIV(params.BlockSize, rand)
	if err != nil {
		return nil, err
	}

	return SymmetricBlockModeEncrypt(cipher.NewCBCEncrypter, blockCipher, iv, key, plaintext), nil

}

// CBCDecrypt performs Cipher Block Chaining (CBC) decryption using the block cipher specified in
// the parameters
func CBCDecrypt(rand io.Reader, params *ECIESParams, key, ciphertext []byte) ([]byte, error) {

	blockCipher, err := params.Cipher(key)
	if err != nil {
		return nil, err
	}

	return SymmetricBlockModeDecrypt(cipher.NewCBCDecrypter, blockCipher, ciphertext[:params.BlockSize], key, ciphertext[params.BlockSize:]), nil

}

// Performs sysmmetric encrypion using the specified block cipher
func SymmetricBlockModeEncrypt(str func(cipher.Block, []byte) cipher.BlockMode, blockCipher cipher.Block, iv []byte, key, plaintext []byte) (ciphertext []byte) {

	// Initialize the cipher
	blockModeCipher := str(blockCipher, iv)

	// Creates a byte sink the size of plaintext plus iv
	ciphertext = make([]byte, len(plaintext)+len(iv))

	// First params.BlockSize bytes are filled with the iv
	copy(ciphertext, iv)

	// The remaining bytes are filled with the encrypted message
	blockModeCipher.CryptBlocks(ciphertext[len(iv):], plaintext)

	return

}

// Performs sysmmetric decryption using the specified block cipher
func SymmetricBlockModeDecrypt(str func(cipher.Block, []byte) cipher.BlockMode, blockCipher cipher.Block, iv []byte, key, ciphertext []byte) []byte {

	// Initialize the cipher
	blockModeCipher := str(blockCipher, iv)

	// Decrypt the ciphertext
	blockModeCipher.CryptBlocks(ciphertext, ciphertext)

	return ciphertext

}
