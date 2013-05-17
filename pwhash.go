// pwhash represents a password hash in Unix modular crypt format (MCF)
package pwhash

import (
	"errors"
	"fmt"
	"strings"
	"encoding/hex"
)

const Separator = "$"

// Hash represents a password digest and associated data.
type Hash struct {
	Name    string
	Options string
	Salt    []byte
	Digest  []byte
}

// Parse extracts a password hash in MCF format into its component parts.
func Parse(mcf string) (*Hash, error) {

	parts := strings.Split(mcf, Separator)

	// see type Hash
	if len(parts) != 5 {
		return nil, fmt.Errorf("pwhash.Parse: Hash string: %s does not match Hash structure", mcf)
	}

	salt, err := hex.DecodeString(parts[3])
	if err != nil {
		return nil, err
	}

	digest, err := hex.DecodeString(parts[4])
	if err != nil {
		return nil, err
	}
		
	hash := &Hash{
		// parts[0] is empty and is unused.
		Name:    parts[1],
		Options: parts[2],
		Salt:    salt,
		Digest:  digest,
	}

	return hash, nil
}

// String returns a password hash string in Hash format.
func (hash *Hash) String() (string, error) {

	if len(hash.Name) == 0 {
		return "", errors.New("pwhash.String: Name is empty")
	}

	if len(hash.Salt) == 0 {
		return "", errors.New("pwhash.String: Salt is empty")
	}

	if len(hash.Digest) == 0 {
		return "", errors.New("pwhash.String: Digest is empty")
	}

	return strings.Join([]string{"", hash.Name, hash.Options, hex.EncodeToString(hash.Salt), hex.EncodeToString(hash.Digest)}, Separator), nil
}
