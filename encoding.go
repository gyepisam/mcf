package mcf

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

// if you add an encoding above, name it below!

func (e Encoding) String() string {
	switch e {
	case BCRYPT:
		return "bcrypt"
	case SCRYPT:
		return "scrypt"
	case PBKDF2:
		return "pbkdf2"
	case CRYPT:
		return "crypt"
	}
	return "unknown"
}

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
