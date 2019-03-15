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

		{"0.84.2", "0.1.0", Greater},
		{"0.84.2", "1.0.0", Less},
	}

	for _, data := range testData {
		if res := getVersion(data.v1, t).Compare(getVersion(data.v2, t)); res != data.result {
			t.Fatalf("%s compare with %s == %d, expected = %d\n", data.v1, data.v2, res, data.result)
		}
	}
}

func TestVersion_CompareOnly(t *testing.T) {
	const (
		allParts        = MajorFlag | MinorFlag | PatchFlag
		majorMinorParts = MajorFlag | MinorFlag
		majorParts      = MajorFlag
		majorPatchParts = MajorFlag | PatchFlag
	)
	testData := []struct {
		v1, v2 string
		result ComparisonStatus
		flag   CompareFlag
	}{
		{"0.0.0", "0.0.0", Equal, allParts},
		{"1.0.0", "0.0.0", Greater, allParts},
		{"0.0.0", "1.0.0", Less, allParts},

		{"0.0.11", "0.0.0", Equal, majorMinorParts},
		{"0.84.11", "0.84.0", Equal, majorMinorParts},

		{"1.0.11", "0.0.0", Greater, majorMinorParts},
		{"0.0.11", "1.0.0", Less, majorMinorParts},

		{"0.11.11", "0.12.0", Equal, majorParts},
		{"1.11.11", "0.11.0", Greater, majorParts},
		{"0.11.11", "1.11.0", Less, majorParts},

		{"0.12.0", "0.21.0", Equal, majorPatchParts},

		// greater due to major part
		{"1.12.0", "0.13.0", Greater, majorPatchParts},
		// greater due to patch part
		{"0.12.1", "0.13.0", Greater, majorPatchParts},

		// less due to major part
		{"0.12.0", "1.10.0", Less, majorPatchParts},
		// less due to patch part
		{"0.12.0", "0.10.1", Less, majorPatchParts},

		// unsupported value
		{"0.0.0", "0.0.0", InvalidFlags, 0},
		// unsupported value
		{"0.0.0", "0.0.0", InvalidFlags, allParts << 1},
	}

	for i, data := range testData {
		if res := getVersion(data.v1, t).CompareOnly(data.flag, getVersion(data.v2, t)); res != data.result {
			t.Fatalf("%d. %s compare only %s with %s == %d, expected = %d\n", i, data.v1, data.flag, data.v2, res, data.result)
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
