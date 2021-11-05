package acrastruct

/*
which symbols can be used - 2 3 4 5 6 7
hex   char dec  bin
'22' - " - 34 - 0b100010
'33' - 3 - 51 - 0b110011
'44' - D - 68 - 0b1000100
'55' - U - 85 - 0b1010101
'66' - f - 102 - 0b1100110
'77' - w - 119 - 0b1110111
<"> decided as less possible occurrence in sequence as 8 bytes in a row
*/

//var TagBegin = []byte{133, 32, 251}

// Constants that setup which symbol would be used at start in AcraStruct to simplify recognizing from other binary data
// Double-quote was chosen because it's printable symbol (help in debugging when we can see in console that it's start of
// AcraStruct) and rarely used sequentially
// Tag length was chosen
const (
	// TagSymbol used in begin tag in AcraStruct
	TagSymbol byte = '"'
)

// TagBegin represents begin sequence of bytes for AcraStruct.
var TagBegin = []byte{TagSymbol, TagSymbol, TagSymbol, TagSymbol, TagSymbol, TagSymbol, TagSymbol, TagSymbol}

// Shows key and data length.
const (
	// length of EC public key
	PublicKeyLength = 45
	// length of 32 byte of symmetric key wrapped to smessage
	SMessageKeyLength = 84
	KeyBlockLength    = PublicKeyLength + SMessageKeyLength

	SymmetricKeySize = 32
	// DataLengthSize length of part of AcraStruct that store data part length. So max data size is 2^^64 that
	// may be wrapped into AcraStruct. We decided that 2^^64 is enough and not much as 8 byte overhead per AcraStruct
	DataLengthSize = 8
)
