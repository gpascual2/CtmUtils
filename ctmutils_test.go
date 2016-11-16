package ctmutils_test

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/gpascual2/ctmutils"
)

func init() {
	fmt.Println("\n>>>> ctmUtils_test : Init")
}

// Test random pass generation. Request 2 consecutive pass and verify they are different.
func TestRandomPassword(t *testing.T) {
	fmt.Println("\n>> ctmUtils_test : TestRandomPassword")
	ctmUtils := ctmutils.New()

	pass1 := ctmUtils.Password(32)
	pass2 := ctmUtils.Password(32)
	fmt.Println("  - Debug - Pass1: ", pass1)
	fmt.Println("  - Debug - Pass2: ", pass2)

	if pass1 == pass2 {
		t.Fail()
	}
}

// Test random key generation. Request 2 consecutive keys and verify they are different.
func TestRandomKey(t *testing.T) {
	fmt.Println("\n>> ctmUtils_test : TestRandomKey")
	ctmUtils := ctmutils.New()

	key1 := ctmUtils.Key(32)
	key2 := ctmUtils.Key(32)
	fmt.Printf("  - Debug - Key1: %x \n", key1)
	fmt.Printf("  - Debug - Key2: %x \n", key2)

	if reflect.DeepEqual(key1, key2) {
		t.Fail()
	}
}

// Test ISO6346 check digit generation
func TestGetCheckDigit(t *testing.T) {
	fmt.Println("\n>> ctmUtils_test : TestGetCheckDigit")
	ctmUtils := ctmutils.New()

	var testsValues = []struct {
		word     string // input
		expected int    // expected result
	}{
		{"CSQU305438", 3},
		{"A1B2", 0},
		{"ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890", 1},
		{"ABCDEFGHIJKLMNOPQRSTUVWXYZ", 0},
		{"1234567890", 5},
		{"", 0},
	}

	for _, tt := range testsValues {
		actual := ctmUtils.CheckDigit(tt.word)
		if actual != tt.expected {
			t.Errorf("  - Debug :: CheckDigit(%v): expected %d, actual %d", tt.word, tt.expected, actual)
		}
	}
}

// Test ISO6346 check digit verification
func TestVerifyCheckDigit(t *testing.T) {
	fmt.Println("\n>> ctmUtils_test : TestVerifyCheckDigit")
	ctmUtils := ctmutils.New()

	var testsValues = []struct {
		word     string // input
		expected bool   // expected result
	}{
		{"CSQU3054383", true},
		{"CSQU3054380", false},
		{"CSQU3054381", false},
		{"CSQU3054382", false},
		{"CSQU3054384", false},
		{"CSQU3054385", false},
		{"CSQU3054386", false},
		{"CSQU3054387", false},
		{"CSQU3054388", false},
		{"CSQU3054389", false},
		{"A1B20", true},
		{"ABCDEFGHIJKLMNOPQRSTUVWXYZ12345678901", true},
		{"ABCDEFGHIJKLMNOPQRSTUVWXYZ0", true},
		{"12345678905", true},
		{"CSQU305438A", false},
	}

	for _, tt := range testsValues {
		actual := ctmUtils.VerifyCheckDigit(tt.word)
		if actual != tt.expected {
			t.Errorf("  - Debug :: VerifyCheckDigit(%v): expected %t, actual %t", tt.word, tt.expected, actual)
		}
	}
}
