package utils

import "fmt"

// function for standartizing custom messages with messages from error
func ErrorMessage(msg string, err error) string {
	return fmt.Sprintf("%v (error message - %v)", msg, err)
}
