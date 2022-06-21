package rsaa

import (
	"log"
	"testing"
)

func TestKeygen(t *testing.T) {
	bitlen := 64
	pub, priv, mat, err := GenerateKeys(bitlen)

	if err != nil {
		t.Fatalf("ERROR: %v", err)
	} else {
		log.Printf("\np: %v\nq: %v\nt: %v\nn: %v\ne: %v\nd: %v\n",
		mat.P, mat.Q, mat.THETA, pub.N, pub.E, priv.D)
	}
}
