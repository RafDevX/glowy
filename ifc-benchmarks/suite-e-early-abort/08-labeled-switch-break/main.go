package main

import "fmt"

// glowy::label::{secret}
const secret = true

// glowy::label::{private}
const private = 5

func main() {
	result := 0
	other := false
	yetAnother := false

Choice:
	switch {
	default:
		if secret {
			for i := range private {
				// glowy::assert::{secret, private}
				fmt.Println(i)

				break Choice
			}

			other = true
		}

		result = 1
		yetAnother = true
	}

	// glowy::assert::{secret, private}
	fmt.Println(result, other, yetAnother)

	clean := 0
	// glowy::assert::{}
	fmt.Println(clean)
}
