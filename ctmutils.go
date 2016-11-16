package ctmutils

import (
	crnd "crypto/rand"
	mrnd "math/rand"
	"time"
)

// CtmUtils - Set of helper functions for random password, keys and IDs generation and verification.
type CtmUtils struct {
}

// New - Constructor
// Returns an instance of CtmUtils
func New() (f *CtmUtils) {
	return new(CtmUtils)
}

// Password - Returns a random password like string of the length requested
// using numbers, symbols, upper and lower case characters.
// Useful for encryption passwords, session or cookies ids.
func (f *CtmUtils) Password(length int) string {
	// Wait for 2 Millisecond to force a different seed on every call
	time.Sleep(2 * time.Millisecond)
	// Set random seed
	mrnd.Seed(time.Now().UTC().UnixNano())
	// Set the symbols set used as template for the password
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-#$%&!@"
	// Calculate random string using the above chars set and with the lenght requested
	result := make([]byte, length)
	for i := 0; i < length; i++ {
		result[i] = chars[mrnd.Intn(len(chars))]
	}
	return string(result)
}

// Password - Returns a random byte key of the length requested.
// Useful for objects ids.
func (f *CtmUtils) Key(length int) []byte {
	key := make([]byte, length)
	_, err := crnd.Read(key)
	if err != nil {
		// handle error here
	}
	return key
}

// Password - Returns a random byte key of the length requested.
// Useful for objects ids.
func (f *CtmUtils) CheckDigit(word string) string {
	var chkDigit string = ""

	return chkDigit
}
