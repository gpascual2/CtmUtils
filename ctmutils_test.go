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

// Verificar que al solicitar 2 contraseñas consecutivas, estas sean distintas
func TestRandomPassword(t *testing.T) {
	fmt.Println("\n>> ctmUtils_test : TestRandomPassword")
	ctmUtils := ctmutils.New()

	pass1 := ctmUtils.Password(32)
	pass2 := ctmUtils.Password(32)
	fmt.Println("  - Debug - Pass1: ", pass1)
	fmt.Println("  - Debug - Pass2: ", pass2)

	// verifico que las pass generadas sean diferentes
	if pass1 == pass2 {
		t.Fail()
	}
}

// Verificar que al solicitar 2 keys consecutivas, estas sean distintas
func TestRandomKey(t *testing.T) {
	fmt.Println("\n>> ctmUtils_test : TestRandomKey")
	ctmUtils := ctmutils.New()

	key1 := ctmUtils.Key(32)
	key2 := ctmUtils.Key(32)
	fmt.Printf("  - Debug - Key1: %x \n", key1)
	fmt.Printf("  - Debug - Key2: %x \n", key2)

	// verifico que las pass generadas sean diferentes
	if reflect.DeepEqual(key1, key2) {
		t.Fail()
	}
}
