package core

import (
	"io"

	"github.com/SoftwareDefinedBuildings/starwave/crypto/cryptutils"
	"github.com/SoftwareDefinedBuildings/starwave/crypto/oaque"
	"golang.org/x/crypto/nacl/secretbox"
)

func HybridEncrypt(random io.Reader, params *oaque.Params, precomputed *oaque.PreparedAttributeList, message []byte) (*oaque.Ciphertext, []byte, error) {
	var key [32]byte
	encryptedKey, err := GenerateEncryptedSymmetricKey(random, params, precomputed, key[:])
	if err != nil {
		return nil, nil, err
	}

	var nonce [24]byte
	buffer := make([]byte, 0, len(message)+secretbox.Overhead)
	output := secretbox.Seal(buffer, message, &nonce, &key)

	return encryptedKey, output, nil
}

func GenerateEncryptedSymmetricKey(random io.Reader, params *oaque.Params, precomputed *oaque.PreparedAttributeList, symm []byte) (*oaque.Ciphertext, error) {
	_, hashesToKey := cryptutils.GenerateKey(symm)
	ct, err := oaque.EncryptPrecomputed(nil, params, precomputed, hashesToKey)
	if err != nil {
		return nil, err
	}
	return ct, nil
}

func HybridDecrypt(encryptedKey *oaque.Ciphertext, encryptedMessage []byte, key *oaque.PrivateKey) ([]byte, bool) {
	var sk [32]byte
	DecryptSymmetricKey(key, encryptedKey, sk[:])

	var nonce [24]byte
	buffer := make([]byte, 0, len(encryptedMessage)-secretbox.Overhead)
	return secretbox.Open(buffer, encryptedMessage, &nonce, &sk)
}

func DecryptSymmetricKey(key *oaque.PrivateKey, encryptedKey *oaque.Ciphertext, symm []byte) []byte {
	hashesToKey := oaque.Decrypt(key, encryptedKey)
	return cryptutils.GTToSecretKey(hashesToKey, symm)
}
