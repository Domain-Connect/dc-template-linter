package internal

import (
	"strings"
	"unicode"
)

// This file contains small helper functions

// StripSpaces will remove all (beginning, middle, or end) whitespace characters from a string
func StripSpaces(str string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			// if the character is a space, drop it
			return -1
		}
		// else keep it in the string
		return r
	}, str)
}
