package main

import "fmt"

// glowy::label::{secret}
const secret = 4

func main() {
	i := 0

Loop:
	i++
	if i < secret {
		goto Loop
	}

	// glowy::assert::{secret}
	fmt.Println(i)
}
