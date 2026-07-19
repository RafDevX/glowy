package main

import "fmt"

// glowy::label::{secret}
const secretText = "é"

func main() {
	text := "A" + secretText + "B"
	for byteIndex, decodedRune := range text {
		// glowy::assert::{secret}
		fmt.Println(byteIndex, decodedRune)
	}

	// glowy::label::{invalid-encoding}
	invalidByte := byte(0xff)

	malformed := string([]byte{'A', invalidByte, 'B'})
	for byteIndex, decodedRune := range malformed {
		// glowy::assert::{}
		fmt.Println(byteIndex)

		// glowy::assert::{invalid-encoding}
		fmt.Println(decodedRune)
	}
}
