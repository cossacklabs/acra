package utils

const (
	SLASH_CHAR = 92
)

// return true if character is ascii printable (code between 32 and 126)
func IsPrintableEscapeChar(c byte) bool {
	if c >= 32 && c <= 126 {
		return true
	} else {
		return false
	}
}
