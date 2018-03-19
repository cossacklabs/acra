package logging

import (
	"testing"
)

func TestStringEscape(t *testing.T) {
	testString := "small string"
	modifiedString := prepareString(testString)

	if modifiedString != testString {
		t.Errorf("Incorrect CEF string escaping <%s>", modifiedString)
	}

	testString = "small | = string"
	modifiedString = prepareString(testString)

	if modifiedString != "small \\| \\= string" {
		t.Errorf("Incorrect CEF string escaping <%s>", modifiedString)
	}

	testString = "small \t \n string"
	modifiedString = prepareString(testString)

	if modifiedString != "small     string" {
		t.Errorf("Incorrect CEF string escaping <%s>", modifiedString)
	}
}