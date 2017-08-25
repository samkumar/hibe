package hibe

import (
	"bytes"
	"crypto/rand"
	"math/big"
	"testing"

	"golang.org/x/crypto/bn256"
)

var LINEAR_HIERARCHY = []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3)}

func NewMessage() *bn256.GT {
	return bn256.Pair(new(bn256.G1).ScalarBaseMult(big.NewInt(3)), new(bn256.G2).ScalarBaseMult(big.NewInt(5)))
}

func TestTopLevel(t *testing.T) {
	// Set up parameters
	params, key, err := Setup(rand.Reader, 10)
	if err != nil {
		t.Fatal(err)
	}

	// Come up with a message to encrypt
	message := NewMessage()

	// Encrypt a message under the top level public key
	ciphertext, err := Encrypt(rand.Reader, params, LINEAR_HIERARCHY[:1], message)
	if err != nil {
		t.Fatal(err)
	}

	// Generate key for the top level
	toplevelkey, err := KeyGenFromMaster(rand.Reader, params, key, LINEAR_HIERARCHY[:1])
	if err != nil {
		t.Fatal(err)
	}

	if toplevelkey.DepthLeft() != 9 {
		t.Fatal("Depth remaining on key is incorrect")
	}

	// Decrypt ciphertext with key and check that it is correct
	decrypted := Decrypt(toplevelkey, ciphertext)
	if !bytes.Equal(message.Marshal(), decrypted.Marshal()) {
		t.Fatal("Original and encrypted messages differ")
	}
}

func TestSecondLevelFromMaster(t *testing.T) {
	// Set up parameters
	params, key, err := Setup(rand.Reader, 10)
	if err != nil {
		t.Fatal(err)
	}

	// Come up with a message to encrypt
	message := NewMessage()

	// Encrypt a message under the second level public key
	ciphertext, err := Encrypt(rand.Reader, params, LINEAR_HIERARCHY[:2], message)
	if err != nil {
		t.Fatal(err)
	}

	// Generate second level key from master key
	secondlevelkey, err := KeyGenFromMaster(rand.Reader, params, key, LINEAR_HIERARCHY[:2])
	if err != nil {
		t.Fatal(err)
	}

	if secondlevelkey.DepthLeft() != 8 {
		t.Fatal("Depth remaining on key is incorrect")
	}

	decrypted := Decrypt(secondlevelkey, ciphertext)
	if !bytes.Equal(message.Marshal(), decrypted.Marshal()) {
		t.Fatal("Original and encrypted messages differ")
	}
}

func TestSecondLevelFromParent(t *testing.T) {
	// Set up parameters
	params, key, err := Setup(rand.Reader, 10)
	if err != nil {
		t.Fatal(err)
	}

	// Come up with a message to encrypt
	message := NewMessage()

	// Encrypt a message under the second level public key
	ciphertext, err := Encrypt(rand.Reader, params, LINEAR_HIERARCHY[:2], message)
	if err != nil {
		t.Fatal(err)
	}

	// Generate top level key from master key
	toplevelkey, err := KeyGenFromMaster(rand.Reader, params, key, LINEAR_HIERARCHY[:1])
	if err != nil {
		t.Fatal(err)
	}

	// Generate second level key from top level key
	secondlevelkey, err := KeyGenFromParent(rand.Reader, params, toplevelkey, LINEAR_HIERARCHY[:2])
	if err != nil {
		t.Fatal(err)
	}

	if secondlevelkey.DepthLeft() != 8 {
		t.Fatal("Depth remaining on key is incorrect")
	}

	decrypted := Decrypt(secondlevelkey, ciphertext)
	if !bytes.Equal(message.Marshal(), decrypted.Marshal()) {
		t.Fatal("Original and encrypted messages differ")
	}
}
