package handlers

import (
	"testing"
)

func TestUtilities(t *testing.T){

	//Test 1
	expected := []string {"x", "y", "z"}

	input := []string {"x", "y", "z", "x", "y"}

	removeDuplicates(&input)

	if !areEqual(input, expected) {
		t.Fatal("unexpected result")
	}

	//Test 2
	expected = []string {"@lagovas", "@vixentael", "@secumod"}
	input = []string {"@lagovas", "@vixentael", "@secumod", "@lagovas", "@vixentael", "@secumod", "@lagovas", "@vixentael", "@secumod"}

	removeDuplicates(&input)

	if !areEqual(input, expected) {
		t.Fatal("unexpected result")
	}

}

func areEqual(a []string, b []string) bool {
	if len(a) != len(b){
		return false
	}

	for index := 0; index < len(a); index++{
		if a[index] != b[index]{
			return false
		}
	}

	return true
}
