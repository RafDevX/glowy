package main

import "fmt"

// glowy::label::{private}
const private = true

func main() {
	result := 0

	for {
		fmt.Println(result)

		if private {
			break
		}

		result = 1
		break
	}

	// glowy::assert::{private}
	fmt.Println(result)
}
