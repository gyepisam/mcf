package scrypt

/* 
  scrypt is a password digest creation and verification library based on scrypt.

  From scrypt sources....

  The recommended parameters for interactive logins as of 2009 are N=16384,
  r=8, p=1. They should be increased as memory latency and CPU parallelism
  increases. Remember to get a good random salt.

 GSAM notes:
    What's a good salt length - 32 bytes
    what's a good password length - minimum 8 bytes, allow up to 100 characters.
    what are the appropriate cost parameters (work factors).
    Cost Calculation: (128 * r * p) + (256 * r) + (128 * n * r)

*/

import (
	digest "code.google.com/p/go.crypto/scrypt"
	"crypto/subtle"
	"fmt"
	"math"
	"strconv"
	"strings"
	"pwhash"
)

// According to the author, the following figures are
// allows a circa 2009 machine to produce a digest in 1 second.
// In 2013, it's probably best to use (N=2^16, r= 10, p=2).
// Ideally, the work factors would increases with each passing year.

type Config struct {
	Name    string
	HashLen int // bytes

	// Costs
	LogN int // Lg(N)
	R    int
	P    int
}

// Name returns item name
func (conf *Config) Id() string {
	return conf.Name
}

// Generate returns an a HashLen long scrypt digest of Password and Salt.
// In the event of an error the return value will be nil and error will be set.
func (conf *Config) Generate(Password, Salt []byte) (*pwhash.Hash, error) {

	h := &pwhash.Hash{
		Name:    conf.Name,
		Options: fmt.Sprintf("%d,%d,%d", conf.LogN, conf.R, conf.P),
		Salt:    Salt,
	}

	var err error
	h.Digest, err = digest.Key(Password, Salt, int(math.Pow(2, float64(conf.LogN))), conf.R, conf.P, conf.HashLen)
	if err != nil {
		return nil, err
	}

	return h, nil
}

// Verify returns true iff the proffered password hashes to the same value
// as the Digest part of h, extracted from a previously generated string.
func (conf *Config) Verify(Password string, h *pwhash.Hash) (bool, error) {

	test_conf := *conf
	test_conf.HashLen = len(h.Digest)

	options := strings.Split(h.Options, ",")
	test_conf.LogN, _ = strconv.Atoi(options[0])
	test_conf.R, _ = strconv.Atoi(options[1])
	test_conf.P, _ = strconv.Atoi(options[2])

	test_hash, err := test_conf.Generate([]byte(Password), h.Salt)
	if err != nil {
		return false, err
	}

	return subtle.ConstantTimeCompare([]byte(h.Digest), []byte(test_hash.Digest)) == 1, nil
}
