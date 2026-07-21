package main

import "fmt"

// glowy::label::{secret}
const secret = true

func main() {
	result := 0

	switch {
	default:
		if secret {
			break
		}

		result = 1
	}

	// glowy::assert::{secret}
	fmt.Println(result)

	clean := 0
	// glowy::assert::{}
	fmt.Println(clean)
}
