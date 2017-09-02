package hibe

import (
	"crypto/sha256"
	"math/big"

	"golang.org/x/crypto/bn256"
)

// geSize is the base size in bytes of a marshalled group element. The size of
// a marshalled element of G2 is geSize. The size of a marshalled element of G1
// is 2 * geSize. The size of a marshalled element of G2 is 6 * geSize.
const geSize = 64

// geShift is the base shift for a marshalled group element
const geShift = 6

func geIndex(encoded []byte, index int, len int) []byte {
	return encoded[index<<geShift : (index+len)<<geShift]
}

// Marshal encodes the parameters as a byte slice.
func (params *Params) Marshal() []byte {
	marshalled := make([]byte, (6+len(params.h))<<geShift)

	copy(geIndex(marshalled, 0, 2), params.g.Marshal())
	copy(geIndex(marshalled, 2, 2), params.g1.Marshal())
	copy(geIndex(marshalled, 4, 1), params.g2.Marshal())
	copy(geIndex(marshalled, 5, 2), params.g3.Marshal())
	for i, hi := range params.h {
		copy(geIndex(marshalled, 6+i, 1), hi.Marshal())
	}

	return marshalled
}

// Unmarshal recovers the parameters from an encoded byte slice.
func (params *Params) Unmarshal(marshalled []byte) (*Params, bool) {
	if len(marshalled)&((1<<geShift)-1) != 0 {
		return nil, false
	}

	params.g = new(bn256.G2)
	if _, ok := params.g.Unmarshal(geIndex(marshalled, 0, 2)); !ok {
		return nil, false
	}

	params.g1 = new(bn256.G2)
	if _, ok := params.g1.Unmarshal(geIndex(marshalled, 2, 2)); !ok {
		return nil, false
	}

	params.g2 = new(bn256.G1)
	if _, ok := params.g2.Unmarshal(geIndex(marshalled, 4, 1)); !ok {
		return nil, false
	}

	params.g3 = new(bn256.G1)
	if _, ok := params.g3.Unmarshal(geIndex(marshalled, 5, 1)); !ok {
		return nil, false
	}

	hlen := (len(marshalled) >> geShift) - 6
	params.h = make([]*bn256.G1, hlen, hlen)
	for i := range params.h {
		hi := new(bn256.G1)
		params.h[i] = hi
		if _, ok := hi.Unmarshal(geIndex(marshalled, 6+i, 1)); !ok {
			return params, false
		}
	}

	// Clear any cached values
	params.pairing = nil

	return params, true
}

// Marshal encodes the private key as a byte slice.
func (key *PrivateKey) Marshal() []byte {
	marshalled := make([]byte, (3+len(key.b))<<geShift)

	copy(geIndex(marshalled, 0, 1), key.a0.Marshal())
	copy(geIndex(marshalled, 1, 2), key.a1.Marshal())
	for i, bi := range key.b {
		copy(geIndex(marshalled, 3+i, 1), bi.Marshal())
	}

	return marshalled
}

// Unmarshal recovers the private key from an encoded byte slice.
func (key *PrivateKey) Unmarshal(marshalled []byte) (*PrivateKey, bool) {
	if len(marshalled)&((1<<geShift)-1) != 0 {
		return nil, false
	}

	key.a0 = new(bn256.G1)
	if _, ok := key.a0.Unmarshal(geIndex(marshalled, 0, 1)); !ok {
		return nil, false
	}

	key.a1 = new(bn256.G2)
	if _, ok := key.a1.Unmarshal(geIndex(marshalled, 1, 2)); !ok {
		return nil, false
	}

	blen := (len(marshalled) >> geShift) - 3
	key.b = make([]*bn256.G1, blen, blen)
	for i := range key.b {
		bi := new(bn256.G1)
		key.b[i] = bi
		if _, ok := bi.Unmarshal(geIndex(marshalled, 3+i, 1)); !ok {
			return key, false
		}
	}

	return key, true
}

// Marshal encodes the ciphertext as a byte slice.
func (ciphertext *Ciphertext) Marshal() []byte {
	marshalled := make([]byte, 9<<geShift)

	copy(geIndex(marshalled, 0, 6), ciphertext.a.Marshal())
	copy(geIndex(marshalled, 6, 2), ciphertext.b.Marshal())
	copy(geIndex(marshalled, 8, 1), ciphertext.c.Marshal())

	return marshalled
}

// Unmarshal recovers the ciphertext from an encoded byte slice.
func (ciphertext *Ciphertext) Unmarshal(marshalled []byte) (*Ciphertext, bool) {
	if len(marshalled) != 9<<geShift {
		return nil, false
	}

	ciphertext.a = new(bn256.GT)
	if _, ok := ciphertext.a.Unmarshal(geIndex(marshalled, 0, 6)); !ok {
		return nil, false
	}
	ciphertext.b = new(bn256.G2)
	if _, ok := ciphertext.b.Unmarshal(geIndex(marshalled, 6, 2)); !ok {
		return nil, false
	}
	ciphertext.c = new(bn256.G1)
	if _, ok := ciphertext.c.Unmarshal(geIndex(marshalled, 8, 1)); !ok {
		return nil, false
	}

	return ciphertext, true
}

// HashToZp hashes a byte slice to an integer in Zp*.
func HashToZp(bytestring []byte) *big.Int {
	digest := sha256.Sum256(bytestring)
	bigint := new(big.Int).SetBytes(digest[:])
	bigint.Mod(bigint, new(big.Int).Add(bn256.Order, big.NewInt(-1)))
	bigint.Add(bigint, big.NewInt(1))
	return bigint
}

// gtBase is e(g1, g2) where g1 and g2 are the base generators of G2 and G1
var gtBase *bn256.GT

// HashToGT hashes a byte slice to a group element in GT.
func HashToGT(bytestring []byte) *bn256.GT {
	if gtBase == nil {
		gtBase = bn256.Pair(new(bn256.G1).ScalarBaseMult(big.NewInt(1)),
			new(bn256.G2).ScalarBaseMult(big.NewInt(1)))
	}
	return new(bn256.GT).ScalarMult(gtBase, HashToZp(bytestring))
}
