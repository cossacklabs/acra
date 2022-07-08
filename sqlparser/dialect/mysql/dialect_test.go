package mysql

import "testing"

func TestNewANSIMySQLDialect(t *testing.T) {
	if !NewMySQLDialect(SetANSIMode(true)).ansiMode {
		t.Fatal("Incorrectly initialized dialect with ANSI mode on")
	}
}

func TestMySQLDialect_IsANSIModeOn(t *testing.T) {
	if !NewMySQLDialect(SetANSIMode(true)).IsModeANSIOn() {
		t.Fatal("Incorrectly set ANSI mode for dialect")
	}

	if NewMySQLDialect().IsModeANSIOn() {
		t.Fatal("Incorrectly set ANSI mode for dialect")
	}
}

func TestNewMySQLDialect(t *testing.T) {
	if NewMySQLDialect().ansiMode {
		t.Fatal("Incorrectly initialized default dialect with ANSI mode off")
	}
}

func TestMySQLDialect_QuoteHandler(t *testing.T) {
	tests := []struct {
		dialect          *MySQLDialect
		expectedANSIMode bool
	}{
		{
			NewMySQLDialect(SetANSIMode(true)),
			true,
		},
		{
			NewMySQLDialect(),
			false,
		},
	}
	for _, test := range tests {
		t.Run("check that ansi mode works for dialects and quote handlers", func(t *testing.T) {
			if test.dialect.QuoteHandler().(*QuoteHandler).IsModeANSIOn() != test.expectedANSIMode {
				t.Fatalf("incorrect set ansi mode for QuoteHandler, took: %t, expecte %t",
					!test.expectedANSIMode, test.expectedANSIMode)
			}
		})
	}
}
