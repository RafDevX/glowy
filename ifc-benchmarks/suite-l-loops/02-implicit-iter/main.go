package main

import "fmt"

// glowy::label::{secret}
const secret = 3

func main() {
	a := 0

	for i := secret; i > 0; i-- {
		a++
	}

	// glowy::assert::{secret}
	fmt.Println(a)
}
