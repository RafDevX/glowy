package main

import "fmt"

// glowy::label::{secret}
const secret = 5

func main() {
	found := 0

	for i := 0; i < 10; i++ {
		if i == secret {
			goto Done
		}

		found = i + 1
	}

Done:
	// glowy::assert::{secret}
	fmt.Println(found)
}
