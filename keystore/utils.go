package keystore

import (
	"fmt"
	"io"
)

// PrintKeysTable prints table which describes keys in a human readable format
// into the writer.
// Code is shared by `acra-keys list` and a couple of tests
func PrintKeysTable(keys []KeyDescription, writer io.Writer) error {
	const (
		purposeHeader = "Key purpose"
		extraIDHeader = "Client"
		idHeader      = "Key ID"
	)

	maxPurposeLen := len(purposeHeader)
	maxExtraIDLen := len(extraIDHeader)
	maxKeyIDLen := len(idHeader)
	for _, key := range keys {
		if len(key.Purpose) > maxPurposeLen {
			maxPurposeLen = len(key.Purpose)
		}
		if len(key.ClientID) > maxExtraIDLen {
			maxExtraIDLen = len(key.ClientID)
		}
		if len(key.ID) > maxKeyIDLen {
			maxKeyIDLen = len(key.ID)
		}
	}

	fmt.Fprintf(writer, "%-*s | %-*s | %s\n", maxPurposeLen, purposeHeader, maxExtraIDLen, extraIDHeader, idHeader)

	separator := make([]byte, maxPurposeLen+maxExtraIDLen+maxKeyIDLen+6)
	for i := range separator {
		separator[i] = '-'
	}
	separator[maxPurposeLen+1] = byte('+')
	separator[maxPurposeLen+maxExtraIDLen+4] = byte('+')
	fmt.Fprintln(writer, string(separator))

	for _, key := range keys {
		var extraID string
		if key.ClientID != nil {
			extraID = string(key.ClientID)
		}
		fmt.Fprintf(writer, "%-*s | %-*s | %s\n", maxPurposeLen, key.Purpose, maxExtraIDLen, extraID, key.ID)
	}
	return nil
}

// PrintRotatedKeysTable prints table which describes keys in a readable format into the writer.
// In format `Key purpose | Client | Creation Time | Key ID`
// Code is shared by `acra-keys list` and a couple of tests
func PrintRotatedKeysTable(keys []KeyDescription, writer io.Writer) error {
	const (
		purposeHeader      = "Key purpose"
		extraIDHeader      = "Client"
		idHeader           = "Key ID"
		creationTimeHeader = "Creation Time"
	)

	maxPurposeLen := len(purposeHeader)
	maxExtraIDLen := len(extraIDHeader)
	maxKeyIDLen := len(idHeader)
	maxCreationTimeLen := len(creationTimeHeader)
	for _, key := range keys {
		if len(key.Purpose) > maxPurposeLen {
			maxPurposeLen = len(key.Purpose)
		}
		if len(key.ClientID) > maxExtraIDLen {
			maxExtraIDLen = len(key.ClientID)
		}
		if len(key.ID) > maxKeyIDLen {
			maxKeyIDLen = len(key.ID)
		}
		if len(key.CreationTime.String()) > maxCreationTimeLen {
			maxCreationTimeLen = len(key.CreationTime.String())
		}
	}

	fmt.Fprint(writer, "\n")
	fmt.Fprint(writer, "Rotated keys: \n")
	fmt.Fprintf(writer, "%-*s | %-*s | %-*s | %s\n", maxPurposeLen, purposeHeader, maxExtraIDLen, extraIDHeader, maxCreationTimeLen, creationTimeHeader, idHeader)

	separator := make([]byte, maxPurposeLen+maxExtraIDLen+maxKeyIDLen+maxCreationTimeLen+6)
	for i := range separator {
		separator[i] = '-'
	}
	separator[maxPurposeLen+1] = byte('+')
	separator[maxPurposeLen+maxExtraIDLen+4] = byte('+')
	separator[maxPurposeLen+maxExtraIDLen+maxCreationTimeLen+7] = byte('+')
	fmt.Fprintln(writer, string(separator))

	for _, key := range keys {
		var extraID string
		if key.ClientID != nil {
			extraID = string(key.ClientID)
		}
		fmt.Fprintf(writer, "%-*s | %-*s | %-*s | %s\n", maxPurposeLen, key.Purpose, maxExtraIDLen, extraID, maxCreationTimeLen, key.CreationTime.String(), key.ID)
	}
	return nil
}
