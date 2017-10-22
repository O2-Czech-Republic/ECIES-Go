package ecies

import (
	"crypto/cipher"
	"io"
)

var (
	CTRCipherMode = SymmetricCipherMode{
		Encryptor: CTREncrypt,
		Decryptor: CTRDecrypt,
	}
	CFBCipherMode = SymmetricCipherMode{
		Encryptor: CFBEncrypt,
		Decryptor: CFBDecrypt,
	}
)

// CTREncrypt carries out CTR encryption using the block cipher specified in the
// parameters.
func CTREncrypt(rand io.Reader, params *ECIESParams, key, plaintext []byte) ([]byte, error) {

	stream, err := params.Cipher(key)
	if err != nil {
		return nil, err
	}

	iv, err := GenerateIV(params.BlockSize, rand)
	if err != nil {
		return nil, err
	}

	return SymmetricStreamEncrypt(cipher.NewCTR, stream, iv, key, plaintext), nil

}

// CTRDecrypt carries out CTR decryption using the block cipher specified in
// the parameters
func CTRDecrypt(rand io.Reader, params *ECIESParams, key, ciphertext []byte) ([]byte, error) {

	stream, err := params.Cipher(key)
	if err != nil {
		return nil, err
	}

	return SymmetricStreamDecrypt(cipher.NewCTR, stream, ciphertext[:params.BlockSize], key, ciphertext[params.BlockSize:]), nil
}

// CFBEncrypt performs Cipher Feedback (CFB) encryption using the block cipher specified in
// the parameters
func CFBEncrypt(rand io.Reader, params *ECIESParams, key, plaintext []byte) ([]byte, error) {

	blockCipher, err := params.Cipher(key)
	if err != nil {
		return nil, err
	}

	iv, err := GenerateIV(params.BlockSize, rand)
	if err != nil {
		return nil, err
	}

	return SymmetricStreamEncrypt(cipher.NewCFBEncrypter, blockCipher, iv, key, plaintext), nil

}

// CFBDecrypt performs Cipher Feedback (CFB) decryption using the block cipher specified in
// the parameters
func CFBDecrypt(rand io.Reader, params *ECIESParams, key, ciphertext []byte) ([]byte, error) {

	blockCipher, err := params.Cipher(key)
	if err != nil {
		return nil, err
	}

	return SymmetricStreamDecrypt(cipher.NewCFBDecrypter, blockCipher, ciphertext[:params.BlockSize], key, ciphertext[params.BlockSize:]), nil

}

// Performs sysmmetric encrypion using the specified stream cipher
func SymmetricStreamEncrypt(str func(cipher.Block, []byte) cipher.Stream, blockCipher cipher.Block, iv []byte, key, plaintext []byte) (ciphertext []byte) {

	// Initialize the cipher
	streamCipher := str(blockCipher, iv)

	// Creates a byte sink the size of plaintext plus iv
	ciphertext = make([]byte, len(plaintext)+len(iv))

	// First params.BlockSize bytes are filled with the iv
	copy(ciphertext, iv)

	// The remaining bytes are filled with the encrypted message
	streamCipher.XORKeyStream(ciphertext[len(iv):], plaintext)

	return

}

// Performs sysmmetric decryption using the specified stream cipher
func SymmetricStreamDecrypt(str func(cipher.Block, []byte) cipher.Stream, blockCipher cipher.Block, iv []byte, key, ciphertext []byte) (plaintext []byte) {

	// Initialize the cipher
	streamCipher := str(blockCipher, iv)

	// Prepare the byte sink
	plaintext = make([]byte, len(ciphertext))

	// Decrypt the ciphertext
	streamCipher.XORKeyStream(plaintext, ciphertext)

	return

}
