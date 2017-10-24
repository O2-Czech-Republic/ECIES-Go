package ecies

import (
	"crypto/cipher"
	"io"
)

var GCMCipherMode = SymmetricCipherMode{
	Encryptor: GCMEncrypt,
	Decryptor: GCMDecrypt,
}

// GCMEncrypt performs Galois/Counter Mode encryption using the block cipher specified in
// the parameters
func GCMEncrypt(rand io.Reader, params *ECIESParams, key, plaintext, authenticationData []byte) (ciphertext []byte, err error) {

	blockCipher, err := params.Cipher(key)
	if err != nil {
		return
	}

	gcmCipher, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return
	}

	nonce, err := GenerateIV(gcmCipher.NonceSize(), rand)
	if err != nil {
		return
	}

	ciphertext = gcmCipher.Seal(nonce, nonce, plaintext, authenticationData)
	return

}

// GCMDecrypt performs Galois/Counter Mode decryption using the block cipher specified in
// the parameters
func GCMDecrypt(rand io.Reader, params *ECIESParams, key, ciphertext, authenticationData []byte) (plaintext []byte, err error) {

	blockCipher, err := params.Cipher(key)
	if err != nil {
		return
	}

	gcmCipher, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return
	}

	nonce := ciphertext[:gcmCipher.NonceSize()]
	plaintext, err = gcmCipher.Open(nil, nonce, ciphertext[gcmCipher.NonceSize():], authenticationData)
	return

}
