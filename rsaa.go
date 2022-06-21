package rsaa

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"math/big"
)

type KeyMaterial struct {
	P     *big.Int `json:"p"`
	Q     *big.Int `json:"q"`
	THETA *big.Int `json:"theta"`
}

type PublicKey struct {
	N *big.Int
	E *big.Int
}

type PrivateKey struct {
	N *big.Int
	D *big.Int
}

func GenerateKeys(bitlen int) (*PublicKey, *PrivateKey, *KeyMaterial, error) {
	numRetries := 0

	for {
		numRetries++
		if numRetries == 10 {
			panic("retrying too many times, something went wrong!")
		}

		p, err := rand.Prime(rand.Reader, bitlen/2)
		if err != nil {
			return nil, nil, nil, err
		}
		q, err := rand.Prime(rand.Reader, bitlen/2)
		if err != nil {
			return nil, nil, nil, err
		}

		// n is p * q
		n := new(big.Int).Set(p)
		n.Mul(n, q)

		if n.BitLen() != bitlen {
			continue
		}

		// theta(n) = (p-1)(q-1)
		pminus := new(big.Int).Set(p).Sub(p, big.NewInt(1))
		qminus := new(big.Int).Set(q).Sub(q, big.NewInt(1))
		totient := new(big.Int).Set(pminus)
		totient.Mul(totient, qminus)

		// e as recommended by PKCS#1 (RFC 2313)
		e := big.NewInt(65537)

		// Calculate the modular multiplicative inverse of e such that:
		//   de = 1 (mod totient)
		d := new(big.Int).ModInverse(e, totient)
		if d == nil {
			continue
		}

		pub := &PublicKey{N: n, E: e}
		priv := &PrivateKey{N: n, D: d}
		keyMat := &KeyMaterial{P: p, Q: q, THETA: totient}
		return pub, priv, keyMat, nil
	}
}

// encrypt performs encryption of the message m using a public key, and returns
// the encrypted cipher.
func encrypt(pub *PublicKey, m *big.Int) *big.Int {
	c := new(big.Int)
	c.Exp(m, pub.E, pub.N)
	return c
}

// decrypt performs decryption of the cipher c using a private key, and returns
// the decrypted message.
func decrypt(priv *PrivateKey, c *big.Int) *big.Int {
	m := new(big.Int)
	m.Exp(c, priv.D, priv.N)
	return m
}

// EncryptRSA encrypts the message m using public key pub and returns the
// encrypted bytes.
func EncryptRSA(pub *PublicKey, m string) ([]byte, error) {
	// Compute length of key in bytes, rounding up.
	keyLen := (pub.N.BitLen() + 7) / 8
	if len(m) > keyLen-11 {
		return nil, fmt.Errorf("len(m)=%v, too long", len(m))
	}

	// Following RFC 2313, using block type 02 as recommended for encryption:
	// EB = 00 || 02 || PS || 00 || D
	psLen := keyLen - len(m) - 3
	eb := make([]byte, keyLen)
	eb[0] = 0x00
	eb[1] = 0x02

	// Fill PS with random non-zero bytes.
	for i := 2; i < 2+psLen; {
		_, err := rand.Read(eb[i : i+1])
		if err != nil {
			return nil, err
		}
		if eb[i] != 0x00 {
			i++
		}
	}
	eb[2+psLen] = 0x00

	// Copy the message m into the rest of the encryption block.
	copy(eb[3+psLen:], m)

	// Now the encryption block is complete; we take it as a m-byte big.Int and
	// RSA-encrypt it with the public key.
	mnum := new(big.Int).SetBytes(eb)
	c := encrypt(pub, mnum)

	// The result is a big.Int, which we want to convert to a byte slice of
	// length keyLen. It's highly likely that the size of c in bytes is keyLen,
	// but in rare cases we may need to pad it on the left with zeros (this only
	// happens if the whole MSB of c is zeros, meaning that it's more than 256
	// times smaller than the modulus).
	padLen := keyLen - len(c.Bytes())
	for i := 0; i < padLen; i++ {
		eb[i] = 0x00
	}
	copy(eb[padLen:], c.Bytes())
	return eb, nil
}

// DecryptRSA decrypts the message c using private key priv and returns the
// decrypted bytes, based on block 02 from PKCS #1 v1.5 (RCS 2313).
func DecryptRSA(priv *PrivateKey, c []byte) ([]byte, error) {
	keyLen := (priv.N.BitLen() + 7) / 8
	if len(c) != keyLen {
		return nil, fmt.Errorf("len(c)=%v, want keyLen=%v", len(c), keyLen)
	}

	// Convert c into a bit.Int and decrypt it using the private key.
	cnum := new(big.Int).SetBytes(c)
	mnum := decrypt(priv, cnum)

	// Write the bytes of mnum into m, left-padding if needed.
	m := make([]byte, keyLen)
	copy(m[keyLen-len(mnum.Bytes()):], mnum.Bytes())

	if m[0] != 0x00 {
		return nil, fmt.Errorf("m[0]=%v, want 0x00", m[0])
	}
	if m[1] != 0x02 {
		return nil, fmt.Errorf("m[1]=%v, want 0x02", m[1])
	}

	endPad := bytes.IndexByte(m[2:], 0x00) + 2
	if endPad < 2 {
		return nil, fmt.Errorf("end of padding not found")
	}

	return m[endPad+1:], nil
}
