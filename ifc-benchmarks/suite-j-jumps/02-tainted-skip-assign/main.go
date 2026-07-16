package main

import "fmt"

// glowy::label::{secret}
const secret = 7

// glowy::label::{high}
const high = 3

func main() {
	x := 0

	if secret%2 == 0 {
		goto After
	}

	x = high

After:
	// glowy::assert::{secret, high}
	fmt.Println(x)
}
