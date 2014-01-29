// Copyright 2014 Gyepi Sam. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/*

Package mcf manages application passwords using a variety of password key derivation functions (bcrypt, scrypt, pbkdf2).

The package provides a simple interface for applications to create, verify and update passwords
with secure defaults that can be easily changed.
It outputs encoded passwords in Modular Crypt Format (http://pythonhosted.org/passlib/modular_crypt_format.html) for easy storage and subsequent verification.

MCF is a self identifying password encoding mechanism that allows for the simultaneous existence of multiple
types and generations of passwords.  This provides a mechanism to easily implement changes in security policies
with respect to algorithms used, increased work factors, salt length, etc without affecting the application or users.

It is useful for applications and web sites that need to support multiple password encoding mechanisms
and/or need to allow for different upgrade policies.

See: (https://www.owasp.org/index.php/Password_Storage_Cheat_Sheet) for more information.

Usage:

Import the mcf package along with at least one encoder.
You can import as many encoders as desired.
The first encoder is used to encode all new passwords.
Subsequent encoders are used to decode.

Note that once an encoder has been superceded (is no longer the first imported encoding)
it must not be removed from the import lists until all existing instances of
that encoding have either been converted to a newer encoding or invalidated.

	import (
	  "github.com/gyepisam/mcf"
	  _ "github.com/gyepisam/mcf/scrypt"
	)

	// A user provides a password at registration or signup.
	username, plaintext := "alibaba", "dfj1A4finbfya9BFDL7d"

	// Generate an encoding using the default
	encoded, err := mcf.Generate(plaintext)
	// error handling elided

    // Insert encoded value and user info in database
    user = db.NewUser()
    user.Username = username
    user.Password = encoded
    err = user.Save()
    // handle errors

To authenticate the user:

	// A user provides a password at login.
	username, plaintext := "alibaba", "dfj1A4finbfya9BFDL7d"

	user, err := db.FindUser("username = $1", username)
	// error handling elided

	isValid, err := mcf.Verify(plaintext, user.Password)
	// error handling elided

	if isValid {
	  // success
	}

When authentication succeeds, it is useful to determine whether the password needs to be re-encoded.
It is the best possible time (also, the only possible time) to do this, since the plaintext password
is available. The final part changes to something like:

	if isValid {
	  go func(plaintext, encoded, username string) {
		if isCurrent, err := mcf.IsCurrent(encoded); err == nil && !isCurrent {
		  encoded, err := mcf.Generate(plaintext)
		  // Update encoded value in database
		}
	  } (plaintext, encoded, user.username)

	  // Success
	}

The update is handled by a go routine because it is not interactive and should not slow down
the user experience. Given that, it is especially important to log errors that might occur.

Changing work factors or implementing other policy changes is similarly simple:

    func init() {
	    config := scrypt.GetConfig()
	    config.LgN++ // double the default work factor
	    scrypt.SetConfig(config)
    }

*/
package mcf

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	. "github.com/gyepisam/mcf/encoder"
)

type instance struct {
	id []byte
	Encoder
}

// Encoding represents a number for an encoder and is used to disambiguate amongst the various encoders.
// Not all encoders will be implemented, installed, or used in any given system.
type Encoding uint8

// Known encodings
const (
	BCRYPT      Encoding = iota // import "github.com/gyepisam/mcf/bcrypt"
	SCRYPT                      // import "github.com/gyepisam/mcf/scrypt"
	PBKDF2                      // import "github.com/gyepisam/mcf/pbkdf2"
	CRYPT                       // Not implemented yet
	maxEncoding                 //Not a valid encoding!
)

func (e Encoding) IsValid() bool {
	return e >= 0 && e < maxEncoding
}

type ErrUnregisteredEncoding struct{ s string }

func (e *ErrUnregisteredEncoding) Error() string { return e.s }

type ErrInvalidEncoding struct{ s string }

func (e *ErrInvalidEncoding) Error() string { return e.s }

func (e Encoding) errInvalid() error {
	return &ErrInvalidEncoding{"invalid encoding: " + string(e)}
}

var (
	defaultEncoding = maxEncoding
	encoders        [maxEncoding]*instance
	errNoEncoder    = errors.New("No matching encoder found")
)

// A SaltMiner is function that takes an int and produces that many random bytes.
// It exists to allow variation in the source of salt.
type SaltMiner func(int) ([]byte, error)

// Register adds an encoder implementation to the list.
// It is expected that each encoder will call Register from an init() function.
// The first encoder imported is used to generate new encoded passwords.
// Subsequent imported encoders, if any, are used to decode.
// See SetDefault() to set the default manually.
func Register(encoding Encoding, encoder Encoder) error {
	if !encoding.IsValid() {
		return encoding.errInvalid()
	}

	id := encoder.Id()
	if len(id) == 0 {
		return fmt.Errorf("empty id: encoding=%s", encoding)
	}

	encoders[encoding] = &instance{id: id, Encoder: encoder}

	// default to first registered encoder.
	if !defaultEncoding.IsValid() {
		defaultEncoding = encoding
	}

	return nil
}

// SetDefault sets the default encoding used to generate passwords which defaults to the first
// registered encoder.
func SetDefault(encoding Encoding) error {
	if !encoding.IsValid() {
		return encoding.errInvalid()
	}
	if encoders[encoding] == nil {
		return &ErrUnregisteredEncoding{fmt.Sprintf("encoding [%s] not registered. Forgot to import?", encoding)}
	}

	defaultEncoding = encoding

	return nil
}

// Generate takes a plaintext password and returns an encoded password in Modular Crypt Format
// generated by the default Encoder.
func Generate(plaintext string) (encoded string, err error) {

	if !defaultEncoding.IsValid() {
		err = errors.New("No encoders registered")
		return
	}

	encoder := encoders[defaultEncoding]
	//This should not happen, but use suspenders anyway.
	if encoder == nil {
		panic(fmt.Sprintf("missing implementation for encoding [%s]", defaultEncoding))
	}

	b, err := encoder.Generate([]byte(plaintext))
	if err != nil {
		return
	}

	return string(b), nil
}

func findInstance(encoded []byte) (Encoding, *instance) {
	for i, e := range encoders {
		if e == nil {
			continue
		}

		if len(encoded) > 0 && bytes.HasPrefix(encoded[1:], e.id) {
			return Encoding(i), e
		}
	}
	return maxEncoding, nil
}

// Verify takes a plaintext password and a encoded password and returns true
// if the password, when encoded by the same encoder, using the same parameters,
// matches the encoded password.
func Verify(plaintext, encoded string) (isValid bool, err error) {
	b := []byte(encoded)
	_, encoder := findInstance(b)
	if encoder == nil {
		return false, errNoEncoder
	}
	return encoder.Verify([]byte(plaintext), b)
}

// IsCurrent returns true if the encoded password was generated by the current encoder with the current parameters.
// If it returns false, then the encoded password should be regenerated and replaced.
func IsCurrent(encoded string) (isCurrent bool, err error) {
	b := []byte(encoded)
	encoding, encoder := findInstance(b)
	if encoder == nil {
		err = errNoEncoder
	} else {
		isCurrent, err = encoder.IsCurrent(b)

		if err == nil && isCurrent {
			// change in encoding scheme?
			isCurrent = encoding == defaultEncoding
		}
	}
	return
}

// Salt produces the specified number of random bytes.
// If a function of type SaltMiner is provided, it is used to produce the salt.
// Otherwise, rand.Reader is used.
func Salt(size int, minerFn SaltMiner) (salt []byte, err error) {

	if minerFn == nil {
	    salt = make([]byte, size)
	    _, err = io.ReadFull(rand.Reader, salt)
	    return
	}

	salt, err = minerFn(size)
	if err == nil {
		if m, n := size, len(salt); m != n {
			err = fmt.Errorf("Short salt read. want: %d, got %d", m, n)
		}
	}
	return
}
