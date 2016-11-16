/*
Copyright (c) 2016, Guillermo Pascual
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
package ctmutils

import (
	crnd "crypto/rand"
	"math"
	mrnd "math/rand"
	"strconv"
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

// VerifyCheckDigit - Verifies if the ISO6346 check digit is correct for the string passed as parameter.
// CheckDigit assumed as last character.
func (f *CtmUtils) VerifyCheckDigit(word string) bool {
	var res bool = false
	sWord := word[0 : len(word)-1]
	sCheckDigit := word[len(word)-1 : len(word)]
	cd := f.CheckDigit(sWord)
	if sCheckDigit == strconv.Itoa(cd) {
		res = true
	}
	return res
}

// GenerateID - Generates an ID string in the following format: AAAA-BBBB-CCCC-DDX
// where the last is a check digit.
// Useful for serial numbers, vouchers, etc.
func (f *CtmUtils) GenerateID() string {
	// Wait for 2 Millisecond and set random seed
	time.Sleep(2 * time.Millisecond)
	mrnd.Seed(time.Now().UTC().UnixNano())
	// Set the symbols set used as template for the ID.
	// All upper case and without O/I 0/1 to minimize mispelling.
	const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	// Calculate random string using the above chars set and with the lenght requested
	resValues := make([]byte, 14)
	for i := 0; i < 14; i++ {
		resValues[i] = chars[mrnd.Intn(len(chars))]
	}
	res := string(resValues)
	// Calculate check digit
	cd := f.CheckDigit(res)
	res += strconv.Itoa(cd)
	// Mask result to the AAAA-BBBB-CCCC-DDX format
	res = f.MaskID(res)
	return res
}

// MaskID - Masks an ID string to the "AAAA-BBBB-CCCC-DDX" format
//   AAAABBBBCCCCDDX --> AAAA-BBBB-CCCC-DDX
func (f *CtmUtils) MaskID(id string) string {
	const separator = "-"
	var res string = ""
	if len(id) == 15 {
		res = id[0:4] + separator + id[4:8] + separator + id[8:12] + separator + id[12:15]
	} else {
		res = id
	}
	return res
}

// UnmaskID - UnMasks an ID string from the "AAAA-BBBB-CCCC-DDX" format.
//   AAAA-BBBB-CCCC-DDX --> AAAABBBBCCCCDDX
func (f *CtmUtils) UnmaskID(id string) string {
	const separator = "-"
	var res string = ""
	if len(id) == 18 && id[4:5] == separator && id[9:10] == separator && id[14:15] == separator {
		res = id[0:4] + id[5:9] + id[10:14] + id[15:18]
	} else {
		res = id
	}
	return res
}

// ValidateID - Validates that the ID passed as parameter is fine.
// UnMasks, checks lenght and CheckDigit of an ID string from the "AAAA-BBBB-CCCC-DDX" or "AAAABBBBCCCCDDX" formats.
func (f *CtmUtils) ValidateID(id string) bool {
	var res bool = false
	str := f.UnmaskID(id)
	if len(str) == 15 {
		if f.VerifyCheckDigit(str) {
			res = true
		}
	}
	return res
}
