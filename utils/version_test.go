package utils

import "testing"

func TestParseVersion(t *testing.T) {
	// > 3 parts of version
	if _, err := ParseVersion("1.1.1.1"); err != ErrInvalidVersionFormat {
		t.Fatalf("Expected error: %s, took: %s", ErrInvalidVersionFormat.Error(), err)
	}

	//  < 3 parts of version
	if _, err := ParseVersion("1.1"); err != ErrInvalidVersionFormat {
		t.Fatalf("Expected error: %s, took: %s", ErrInvalidVersionFormat.Error(), err)
	}

	//  empty version part
	if _, err := ParseVersion("1.1."); err == nil {
		t.Fatal("Expected error but took nil")
	}
}

func getVersion(v string, t *testing.T) *Version {
	version, err := ParseVersion(v)
	if err != nil {
		t.Fatal(err)
	}
	return version
}

func TestVersion_Compare(t *testing.T) {
	testData := []struct {
		v1, v2 string
		result ComparisonStatus
	}{
		{"0.0.0", "0.0.0", Equal},
		{"1.0.0", "0.0.0", Greater},
		{"0.0.0", "1.0.0", Less},

		{"0.1.0", "0.0.0", Greater},
		{"0.0.0", "0.1.0", Less},

		{"0.0.1", "0.0.0", Greater},
		{"0.0.0", "0.0.1", Less},

		{"10.0.0", "1.0.0", Greater},
		{"0.0.0", "10.0.0", Less},

		{"1.10.0", "1.1.0", Greater},
		{"1.1.0", "1.10.0", Less},

		{"1.1.10", "1.1.1", Greater},
		{"1.1.1", "1.1.10", Less},
	}

	for _, data := range testData {
		if res := getVersion(data.v1, t).Compare(getVersion(data.v2, t)); res != data.result {
			t.Fatalf("%s compare with %s == %d, expected = %d\n", data.v1, data.v2, res, data.result)
		}
	}

}

func TestGetParsedVersion(t *testing.T) {
	if version, err := GetParsedVersion(); err != nil {
		t.Fatal(err)
	} else {
		if version.Compare(getVersion(VERSION, t)) != Equal {
			t.Fatal("GetParsedVersion != VERSION")
		}
	}
}
