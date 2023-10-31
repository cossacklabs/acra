package common

import (
	"testing"
)

func TestValidateOnFail(t *testing.T) {
	type testcase struct {
		input       string
		expectError bool
	}

	testcases := []testcase{
		{"", false},
		{"error", false},
		{"default_value", false},
		{"ciphertext", false},
		{"gibberish", true},
	}

	for _, testcase := range testcases {
		err := ValidateOnFail(ResponseOnFail(testcase.input))

		if testcase.expectError && err == nil {
			t.Fatalf("[%s] expected error but found nothing", testcase.input)
		} else if !testcase.expectError && err != nil {
			t.Fatalf("[%s] expected not errors, but found %s", testcase.input, err)
		}
	}
}
