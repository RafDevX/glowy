package main

import "fmt"

// glowy::label::{secret}
const secret = true

func main() {
	result := 0

	for i := 0; i < 1; i++ {
		switch {
		default:
			if secret {
				continue
			}
		}

		result = 1
	}

	// glowy::assert::{secret}
	fmt.Println(result)
}
