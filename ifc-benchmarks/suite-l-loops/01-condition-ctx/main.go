package main

import "fmt"

func main() {
	// glowy::label::{private}
	x := 5

	// glowy::label::{high}
	i := 1

	for i <= 3 {
		// glowy::assert::{high}
		fmt.Println(0)

		i += 1
		x += 1
	}

	// glowy::assert::{private, high}
	fmt.Println(x)
}
