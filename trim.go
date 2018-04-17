package pto3trace

import "unicode"

// TrimSpace removes leading and trailing spaces from bytes.
// Unlike strings.TrimSpace(), this function works on []byte,
// not string. It has the same effect as calling
// []byte(strings.TrimSpace(string(bytes))), just without all
// the conversions.
//
// ATTENTION: This routine will only work if bytes consists
// exclusvely of 7-bit ASCII characters.
func TrimSpace(bytes []byte) []byte {
	var start int

	// Assume that the file only contains 7-bit ASCII. Otherwise the conversion
	// from byte to rune will go wrong.
	for start = 0; start < len(bytes) && unicode.IsSpace(rune(bytes[start])); start++ {
	}

	if start == len(bytes) {
		// empty slice
		return bytes[0:0]
	}

	var end int
	for end = len(bytes) - 1; end >= start && unicode.IsSpace(rune(bytes[end])); end-- {
	}

	return bytes[start : end+1]
}
