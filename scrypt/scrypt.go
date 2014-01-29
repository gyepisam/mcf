// Package scrypt uses scrypt to encode passwords for the mcf framework.
package scrypt

import (
	"code.google.com/p/go.crypto/scrypt"

	"fmt"

	"github.com/gyepisam/mcf"
	"github.com/gyepisam/mcf/bridge"
)

// Config has all the twiddlable bits.
type Config struct {
	KeyLen int //Key output Size

	SaltLen int // Length of salt in bytes.

	LgN int // Base2 log of the CPU/Memory cost
	R   int // block size parameter
	P   int // parallelization parameter
}

// Custom source of salt, normally unset.
// Set this if you need to use a custom salt producer.
// Also useful for testing.
var SaltMine mcf.SaltMiner = nil

// Circa 2014 work factors.
// These are exported to show default values.
// See GetConfig and SetConfig(...) to change them.
const (
	DefaultKeyLen  = 128
	DefaultSaltLen = 16
	DefaultLgN     = 16
	DefaultR       = 10
	DefaultP       = 2
)

type ErrInvalidParameter struct {
	Name  string
	Value int
}

func (e ErrInvalidParameter) Error() string {
	return fmt.Sprintf("parameter %s has invalid value: %d", e.Name, e.Value)
}

// Config returns the default configuration used to generate new password hashes.
// The return value  can be modified and used as a parameter to SetConfig
func GetConfig() Config {
	return Config{
		KeyLen:  DefaultKeyLen,
		SaltLen: DefaultSaltLen,
		LgN:     DefaultLgN,
		R:       DefaultR,
		P:       DefaultP,
	}
}

/*
SetConfig sets the default encoding parameters, salt length or key length.
It is best to modify a copy of the default configuration unless all parameters are changed.

Here is an example that doubles the default work factor.

	config := scrypt.GetConfig()
	config.LgN++
	scrypt.SetConfig(config)

*/
func SetConfig(config Config) error {
	c := &config
	err := c.validate()
	if err != nil {
		return err
	}

	return register(config)
}

func register(config Config) error {
	// Constructor function. Provide fresh copy each time.
	fn := func() bridge.Implementer {
		c := config
		return &c
	}

	enc := bridge.New([]byte("scrypt"), fn)

	return mcf.Register(mcf.SCRYPT, enc)
}

func init() {
	err := register(GetConfig())
	if err != nil {
		panic(err)
	}
}

func (c *Config) validate() error {
	slots := []struct {
		n string
		v int
	}{
		{"KeyLen", c.KeyLen},
		{"LgN", c.LgN},
		{"R", c.R},
		{"P", c.P},
	}

	for _, slot := range slots {
		if slot.v <= 0 {
			return ErrInvalidParameter{slot.n, slot.v}
		}
	}

	return nil
}

// Keep these together.
var format = "KeyLen=%d,LgN=%d,R=%d,P=%d"

// Params returns the current digest generation parameters.
func (c *Config) Params() string {
	return fmt.Sprintf(format, c.KeyLen, c.LgN, c.R, c.P)
}

// SetParams sets the parameters for digest generation.
func (c *Config) SetParams(s string) error {
	_, err := fmt.Sscanf(s, format, &c.KeyLen, &c.LgN, &c.R, &c.P)
	if err != nil {
		return err
	}
	return c.validate()
}

// Salt produces SaltLen bytes of random data.
func (c *Config) Salt() ([]byte, error) {
    return mcf.Salt(c.SaltLen, SaltMine)
}

// Key returns a KeyLen long bytes of an scrypt digest of password and salt using the specified parameters.
func (c *Config) Key(plaintext []byte, salt []byte) (b []byte, err error) {
	return scrypt.Key(plaintext, salt, 1<<uint(c.LgN), c.R, c.P, c.KeyLen)
}

// AtLeast returns true if the parameters used to generate the encoded password
// are at least as good as those currently in use.
func (c *Config) AtLeast(current_imp bridge.Implementer) bool {
	current := current_imp.(*Config) // ok to panic
	return !(c.LgN < current.LgN || c.R < current.R || c.P < current.P || c.KeyLen < current.KeyLen)
}
