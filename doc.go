/*
Package mcf is a Go library for creating, verifying, upgrading and managing bcrypt, scrypt, and pbkdf2 password hashes.

mcf provides a simple API for applications to use a variety of
password hashing schemes as well a management mechanism to easily and
transparently set the default password scheme, change schemes, or change
scheme parameters such as work factors, salt length, key length without
rewriting the application.

Usage:

Import the mcf package along with at least one encoder.
You can import as many encoders as desired.
The first encoder is used to encode all new passwords.
Subsequent encoders are used to decode.
There's an API to set the default encoder.

Note that once an encoder has been superceded (is no longer the first imported encoding)
it must not be removed from the import lists until all existing instances of
that encoding have either been converted to a newer encoding or invalidated.

	import (
	  "github.com/gyepisam/mcf"
	  _ "github.com/gyepisam/mcf/scrypt"
	)

	// A user provides a password at registration or signup.
	username, plaintext := "alibaba", "dfj1A4finbfya9BFDL7d"

	// Create an encoding using the default
	encoded, err := mcf.Create(plaintext)
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

When authentication succeeds, it is useful to determine whether the password needs to be re-encoded.
It is the best possible time (also, the only possible time) to do this, since the plaintext password
is available. The final part changes to something like:

	if isValid {
	  go func(plaintext, encoded, username string) {
            isCurrent, err := mcf.IsCurrent(encoded)
            // error handling elided but assumed to return.
		    if !isCurrent {
		      encoded, err := mcf.Create(plaintext)
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

Later, if you decide to switch to pbkdf2, just import it


	 _ "github.com/gyepisam/mcf/pbkdf2"

and make sure it is the current encoder.

    mcf.SetDefault(mcf.PBKDF2)

All subsequently created password will use the new scheme. If you also use the auto upgrade mechanism, then
users will be upgraded upon login as well.

*/
package mcf
