package ecies

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/subtle"
	"fmt"
	"hash"
	"io"
	"math"
	"math/big"
)

var (
	ErrImport                     = fmt.Errorf("ecies: failed to import key")
	ErrInvalidCurve               = fmt.Errorf("ecies: invalid elliptic curve")
	ErrInvalidParams              = fmt.Errorf("ecies: invalid ECIES parameters")
	ErrInvalidPublicKey           = fmt.Errorf("ecies: invalid public key")
	ErrSharedKeyIsPointAtInfinity = fmt.Errorf("ecies: shared key is point at infinity")
	ErrSharedKeyTooBig            = fmt.Errorf("ecies: shared key params are too big")
)

// PublicKey is a representation of an elliptic curve public key.
type PublicKey struct {
	X *big.Int
	Y *big.Int
	elliptic.Curve
	Params *ECIESParams
}

// Export an ECIES public key as an ECDSA public key.
func (pub *PublicKey) ExportECDSA() *ecdsa.PublicKey {
	return &ecdsa.PublicKey{Curve: pub.Curve, X: pub.X, Y: pub.Y}
}

// Import an ECDSA public key as an ECIES public key.
func ImportECDSAPublic(pub *ecdsa.PublicKey) *PublicKey {
	return &PublicKey{
		X:      pub.X,
		Y:      pub.Y,
		Curve:  pub.Curve,
		Params: ParamsFromCurve(pub.Curve),
	}
}

// PrivateKey is a representation of an elliptic curve private key.
type PrivateKey struct {
	PublicKey
	D *big.Int
}

// Export an ECIES private key as an ECDSA private key.
func (prv *PrivateKey) ExportECDSA() *ecdsa.PrivateKey {
	pub := &prv.PublicKey
	pubECDSA := pub.ExportECDSA()
	return &ecdsa.PrivateKey{PublicKey: *pubECDSA, D: prv.D}
}

// Import an ECDSA private key as an ECIES private key.
func ImportECDSA(prv *ecdsa.PrivateKey) *PrivateKey {
	pub := ImportECDSAPublic(&prv.PublicKey)
	return &PrivateKey{*pub, prv.D}
}

// Generate an elliptic curve public / private keypair. If params is nil,
// the recommended default parameters for the key will be chosen.
func GenerateKey(rand io.Reader, curve elliptic.Curve, params *ECIESParams) (prv *PrivateKey, err error) {
	pb, x, y, err := elliptic.GenerateKey(curve, rand)
	if err != nil {
		return
	}
	prv = new(PrivateKey)
	prv.PublicKey.X = x
	prv.PublicKey.Y = y
	prv.PublicKey.Curve = curve
	prv.D = new(big.Int).SetBytes(pb)
	if params == nil {
		params = ParamsFromCurve(curve)
	}
	prv.PublicKey.Params = params
	return
}

// MaxSharedKeyLength returns the maximum length of the shared key the
// public key can produce.
func MaxSharedKeyLength(pub *PublicKey) int {
	return (pub.Curve.Params().BitSize + 7) / 8
}

// ECDH key agreement method used to establish secret keys for encryption.
func (prv *PrivateKey) GenerateShared(pub *PublicKey, keyLength int) (sk []byte, err error) {

	if prv.PublicKey.Curve != pub.Curve {
		return nil, ErrInvalidCurve
	}

	if keyLength > MaxSharedKeyLength(pub) {
		return nil, ErrSharedKeyTooBig
	}

	x, _ := pub.Curve.ScalarMult(pub.X, pub.Y, prv.D.Bytes())
	if x == nil {
		return nil, ErrSharedKeyIsPointAtInfinity
	}

	sk = make([]byte, keyLength)
	skBytes := x.Bytes()
	copy(sk[int(math.Max(0, float64(len(sk)-len(skBytes)))):], skBytes)
	return sk, nil
}

var (
	ErrKeyDataTooLong = fmt.Errorf("ecies: can't supply requested key data")
	ErrSharedTooLong  = fmt.Errorf("ecies: shared secret is too long")
	ErrInvalidMessage = fmt.Errorf("ecies: invalid message")
)

var (
	big2To32   = new(big.Int).Exp(big.NewInt(2), big.NewInt(32), nil)
	big2To32M1 = new(big.Int).Sub(big2To32, big.NewInt(1))
)

func incCounter(ctr []byte) {
	if ctr[3]++; ctr[3] != 0 {
		return
	}
	if ctr[2]++; ctr[2] != 0 {
		return
	}
	if ctr[1]++; ctr[1] != 0 {
		return
	}
	if ctr[0]++; ctr[0] != 0 {
		return
	}
}

// ConcatKDF derives a symmetric key from a shared secret using
// a concatenation key derivation function using the `hash` hashing
// algorithm as the base and continuing until at least `derivedKeyLength`
// bytes is available
// See NIST SP 800-56 Concatenation Key Derivation Function (see section 5.8.1).
func ConcatKDF(hash hash.Hash, sharedSecret, sharedInformation1 []byte, derivedKeyLength int) (derivedKey []byte, err error) {

	if sharedInformation1 == nil {
		sharedInformation1 = make([]byte, 0)
	}

	reps := ((derivedKeyLength + 7) * 8) / (hash.BlockSize() * 8)
	if big.NewInt(int64(reps)).Cmp(big2To32M1) > 0 {
		fmt.Println(big2To32M1)
		return nil, ErrKeyDataTooLong
	}

	counter := []byte{0, 0, 0, 1}
	derivedKey = make([]byte, 0)

	for i := 0; i <= reps; i++ {
		hash.Write(counter)
		hash.Write(sharedSecret)
		hash.Write(sharedInformation1)
		derivedKey = append(derivedKey, hash.Sum(nil)...)
		hash.Reset()
		incCounter(counter)
	}

	// Trim the desired key length to derivedKeyLength
	derivedKey = derivedKey[:derivedKeyLength]
	return
}

// MessageTag computes the MAC of a message (called the tag) as per
// SEC 1, 3.5.
func MessageTag(hash func() hash.Hash, key, msg, shared []byte) []byte {
	mac := hmac.New(hash, key)
	mac.Write(msg)
	mac.Write(shared)
	tag := mac.Sum(nil)
	return tag
}

// Encrypt encrypts a message using ECIES as specified in SEC 1, 5.1.
//
// sharedInformation1 and sharedInformation2 contain shared information that is not part of the resulting
// ciphertext. sharedInformation1 is fed into key derivation, sharedInformation2 is fed into the MAC. If the
// shared information parameters aren't being used, they should be nil.
func Encrypt(rand io.Reader, pub *PublicKey, plaintext, sharedInformation1, sharedInformation2 []byte) (ciphertext []byte, err error) {

	params := pub.Params
	if params == nil {
		if params = ParamsFromCurve(pub.Curve); params == nil {
			err = ErrUnsupportedECIESParameters
			return
		}
	}

	// Generate an ephemeral key pair
	privateKey, err := GenerateKey(rand, pub.Curve, params)
	if err != nil {
		return
	}

	// Serialize the properties of the used elliptic curve
	curveParams := elliptic.Marshal(pub.Curve, privateKey.PublicKey.X, privateKey.PublicKey.Y)

	symmetricKeyLength := params.KeyLen
	macKeyLength := params.KeyLen

	// Derive a shared secret from the generated private key and the peer public key
	sharedSecret, err := privateKey.GenerateShared(pub, symmetricKeyLength+macKeyLength)
	if err != nil {
		return
	}

	// Extend the shared secret through Concatenation KDF to the desired length
	// The extended key will then be split and used as an encryption key and digest key
	hash := params.Hash()
	derivedKey, err := ConcatKDF(hash, sharedSecret, sharedInformation1, symmetricKeyLength+macKeyLength)
	if err != nil {
		return
	}

	// The derived key is split into encryption key and digest key
	// which is then hashed to produce the final HMAC key
	encryptionKey := derivedKey[:symmetricKeyLength]

	digestKey := derivedKey[symmetricKeyLength:]
	hash.Write(digestKey)
	digestKey = hash.Sum(nil)
	hash.Reset()

	// Encrypt the message using the first half of the derived symmetric key
	encryptedMessage, err := SymmetricEncrypt(rand, params, encryptionKey, plaintext, nil)
	if err != nil || len(encryptedMessage) <= params.BlockSize {
		return
	}

	// Calculate message digest of the ciphertext using the specified hashing function
	// and the second half of the derived symmetric key
	digest := MessageTag(params.Hash, digestKey, encryptedMessage, sharedInformation2)

	// Prepare ciphertext byte sink
	ciphertext = make([]byte, len(curveParams)+len(encryptedMessage)+len(digest))

	// Fill the ciphertext byte sink with:
	//   1. marshalled curve properties
	//   2. encrypted message
	//   3. message digest for integrity checking
	copy(ciphertext, curveParams)
	copy(ciphertext[len(curveParams):], encryptedMessage)
	copy(ciphertext[len(curveParams)+len(encryptedMessage):], digest)
	return
}

// Decrypt decrypts an ECIES ciphertext.
func (privateKey *PrivateKey) Decrypt(rand io.Reader, ciphertext, sharedInformation1, sharedInformation2 []byte) (plaintext []byte, err error) {

	if len(ciphertext) == 0 {
		return nil, ErrInvalidMessage
	}

	params := privateKey.PublicKey.Params
	if params == nil {
		if params = ParamsFromCurve(privateKey.PublicKey.Curve); params == nil {
			err = ErrUnsupportedECIESParameters
			return
		}
	}

	hash := params.Hash()

	var (
		curveParamsLength int
		hashLength        int = hash.Size()
		messageStart      int
		messageEnd        int
	)

	switch ciphertext[0] {
	case 2, 3, 4:
		curveParamsLength = ((privateKey.PublicKey.Curve.Params().BitSize + 7) / 4)
		if len(ciphertext) < (curveParamsLength + hashLength + 1) {
			err = ErrInvalidMessage
			return
		}
	default:
		err = ErrInvalidPublicKey
		return
	}

	messageStart = curveParamsLength
	messageEnd = len(ciphertext) - hashLength

	publicKey := new(PublicKey)
	publicKey.Curve = privateKey.PublicKey.Curve
	publicKey.X, publicKey.Y = elliptic.Unmarshal(publicKey.Curve, ciphertext[:curveParamsLength])

	if publicKey.X == nil {
		err = ErrInvalidPublicKey
		return
	}

	if !publicKey.Curve.IsOnCurve(publicKey.X, publicKey.Y) {
		err = ErrInvalidCurve
		return
	}

	sharedSecret, err := privateKey.GenerateShared(publicKey, params.KeyLen+params.KeyLen)
	if err != nil {
		return
	}

	derivedKey, err := ConcatKDF(hash, sharedSecret, sharedInformation1, params.KeyLen+params.KeyLen)
	if err != nil {
		return
	}

	encryptionKey := derivedKey[:params.KeyLen]
	digestKey := derivedKey[params.KeyLen:]
	hash.Write(digestKey)
	digestKey = hash.Sum(nil)
	hash.Reset()

	digest := MessageTag(params.Hash, digestKey, ciphertext[messageStart:messageEnd], sharedInformation2)
	if subtle.ConstantTimeCompare(ciphertext[messageEnd:], digest) != 1 {
		err = ErrInvalidMessage
		return
	}

	plaintext, err = SymmetricDecrypt(rand, params, encryptionKey, ciphertext[messageStart:messageEnd], nil)
	return
}

// Galois/Counter Mode is an AEAD (authenticated cipher) - i.e. it is already
// authenticated and does not require additional tagging to protect the message
// integrity
func EncryptAEAD(rand io.Reader, pub *PublicKey, plaintext []byte) (ciphertext []byte, err error) {

	params := pub.Params
	if params == nil {
		if params = ParamsFromCurve(pub.Curve); params == nil {
			err = ErrUnsupportedECIESParameters
			return
		}
	}

	// Generate an ephemeral key pair
	privateKey, err := GenerateKey(rand, pub.Curve, params)
	if err != nil {
		return
	}

	// Serialize the properties of the used elliptic curve
	curveParams := elliptic.Marshal(pub.Curve, privateKey.PublicKey.X, privateKey.PublicKey.Y)

	symmetricKeyLength := 128 / 8

	if params.KeyLen > 256/8 {
		symmetricKeyLength = 256 / 8
	}

	// Derive a shared secret from the generated private key and the peer public key
	sharedSecret, err := privateKey.GenerateShared(pub, params.KeyLen)
	if err != nil {
		return
	}

	// Extend the shared secret through Concatenation KDF to the desired length
	// The extended key will then be split and used as an encryption key and digest key
	// The properties of the ephemeral public key are used as sharedInfo for the KDF
	sharedInfoKDF := elliptic.Marshal(privateKey.PublicKey.Curve, privateKey.PublicKey.X, privateKey.PublicKey.Y)
	encryptionKey, err := ConcatKDF(params.Hash(), sharedSecret, sharedInfoKDF, symmetricKeyLength)
	if err != nil {
		return
	}

	// Encrypt the message using the first half of the derived symmetric key
	// The properties of the static public key are used as authentication data for
	// the encryption
	authenticationData := elliptic.Marshal(pub.Curve, pub.X, pub.Y)
	encryptedMessage, err := SymmetricEncrypt(rand, params, encryptionKey, plaintext, authenticationData)
	if err != nil || len(encryptedMessage) <= params.BlockSize {
		return
	}

	// Prepare ciphertext byte sink
	ciphertext = make([]byte, len(curveParams)+len(encryptedMessage))

	// Fill the ciphertext byte sink with:
	//   1. marshalled curve properties
	//   2. encrypted message
	copy(ciphertext, curveParams)
	copy(ciphertext[len(curveParams):], encryptedMessage)

	return

}

// Decryption in AEAD mode (w/o message tag)
func (privateKey *PrivateKey) DecryptAEAD(rand io.Reader, ciphertext []byte) (plaintext []byte, err error) {

	if len(ciphertext) == 0 {
		return nil, ErrInvalidMessage
	}

	params := privateKey.PublicKey.Params
	if params == nil {
		if params = ParamsFromCurve(privateKey.PublicKey.Curve); params == nil {
			err = ErrUnsupportedECIESParameters
			return
		}
	}

	hash := params.Hash()

	var curveParamsLength int

	switch ciphertext[0] {
	case 2, 3, 4:
		curveParamsLength = ((privateKey.PublicKey.Curve.Params().BitSize + 7) / 4)
		if len(ciphertext) < (curveParamsLength + 1) {
			err = ErrInvalidMessage
			return
		}
	default:
		err = ErrInvalidPublicKey
		return
	}

	publicKey := new(PublicKey)
	publicKey.Curve = privateKey.PublicKey.Curve
	publicKey.X, publicKey.Y = elliptic.Unmarshal(publicKey.Curve, ciphertext[:curveParamsLength])

	if publicKey.X == nil {
		err = ErrInvalidPublicKey
		return
	}

	if !publicKey.Curve.IsOnCurve(publicKey.X, publicKey.Y) {
		err = ErrInvalidCurve
		return
	}

	// Serialize the properties of the used elliptic curve for use
	// as authentication data
	curveParams := elliptic.Marshal(publicKey.Curve, publicKey.X, publicKey.Y)

	symmetricKeyLength := 128 / 8

	if params.KeyLen > 256/8 {
		symmetricKeyLength = 256 / 8
	}

	sharedSecret, err := privateKey.GenerateShared(publicKey, params.KeyLen)
	if err != nil {
		return
	}

	encryptionKey, err := ConcatKDF(hash, sharedSecret, curveParams, symmetricKeyLength)
	if err != nil {
		return
	}

	authenticationData := elliptic.Marshal(privateKey.PublicKey.Curve, privateKey.PublicKey.X, privateKey.PublicKey.Y)
	plaintext, err = SymmetricDecrypt(rand, params, encryptionKey, ciphertext[curveParamsLength:], authenticationData)
	return

}
