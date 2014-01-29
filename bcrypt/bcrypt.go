// Package bcrypt implements a password encoding mechanism for the mcf framework
package bcrypt

import (
	"code.google.com/p/go.crypto/bcrypt"
	"github.com/gyepisam/mcf"
)

// DefaultCost is the base 2 logarithm of the Bcrypt work factor
// Is is exported here for documentation purposes only.
// Use SetCost() to change it
const DefaultCost = 12

type config struct {
	Cost int
}

func register(c config) error {
	return mcf.Register(mcf.BCRYPT, &c)
}

func init() {
	err := register(config{DefaultCost})
	if err != nil {
		panic(err)
	}
}

func SetCost(cost int) error {
	if cost < bcrypt.MinCost || cost > bcrypt.MaxCost {
		return bcrypt.InvalidCostError(cost)
	}
	return register(config{cost})
}

func (c *config) Id() []byte {
	return []byte("bcrypt")
}

func (c *config) Generate(plaintext []byte) (encoded []byte, err error) {
	return bcrypt.GenerateFromPassword(plaintext, c.Cost)
}

func (c *config) Verify(plaintext, encoded []byte) (isValid bool, err error) {
	err = bcrypt.CompareHashAndPassword(plaintext, encoded)
	isValid = err == nil
	if err == bcrypt.ErrMismatchedHashAndPassword {
		err = nil
	}
	return
}

func (c *config) IsCurrent(encoded []byte) (isCurrent bool, err error) {
	cost, err := bcrypt.Cost(encoded)
	if err == nil {
		isCurrent = cost >= c.Cost
	}
	return
}
