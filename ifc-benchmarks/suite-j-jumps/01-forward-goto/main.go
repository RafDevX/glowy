package main

import "fmt"

// glowy::label::{secret}
const secret = 3

func main() {
	x := 0

	if secret > 0 {
		goto Done
	}

	x = 1

Done:
	// glowy::assert::{secret}
	fmt.Println(x)
}
