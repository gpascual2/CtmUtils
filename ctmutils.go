package ctmutils

import (
	crnd "crypto/rand"
	"math"
	mrnd "math/rand"
	"strings"
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

// CheckDigit - Calculates the ISO6346 check digit for the string passed as parameter.
func (f *CtmUtils) CheckDigit(word string) int {
	var compute int = 0
	var digitSum float64 = 0
	var digitValue int = 0
	var multiFactor float64 = 0

	// First, ensure word is all uppercase
	word = strings.ToUpper(word)

	// map for char conversion
	conversion := map[string]int{
		"A": 10, "B": 12, "C": 13, "D": 14, "E": 15,
		"F": 16, "G": 17, "H": 18, "I": 19, "J": 20,
		"K": 21, "L": 23, "M": 24, "N": 25, "O": 26,
		"P": 27, "Q": 28, "R": 29, "S": 30, "T": 31,
		"U": 32, "V": 34, "W": 35, "X": 36, "Y": 37, "Z": 38,
		"0": 0, "1": 1, "2": 2, "3": 3, "4": 4,
		"5": 5, "6": 6, "7": 7, "8": 8, "9": 9,
	}

	// (I) Get the sum of the product of the converted values with the position factor
	for i := 0; i < len(word); i++ {
		multiFactor = math.Exp2(float64(i))
		digitValue = conversion[word[i:i+1]]
		digitSum += float64(digitValue) * multiFactor
	}
	// (II) Divide sum by 11
	// (III) Round the result down to zero (make the result a whole number (integer))
	// (IV) Multiply the integer value by 11
	compute = int(digitSum/11) * 11
	// (V) Subtract result of (IV) from result of (I): This is the check digit.
	compute = int(digitSum) - compute
	// If result is 10, then replace to 0
	if compute == 10 {
		compute = 0
	}

	return compute
}
