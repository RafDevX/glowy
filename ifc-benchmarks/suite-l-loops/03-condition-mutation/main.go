package main

import "fmt"

func main() {
	// glowy::label::{secret}
	step := 4
	j := 0

	for j <= 10 {
		// glowy::assert::{secret}
		fmt.Println(0)

		j += step
	}

	// glowy::assert::{secret}
	var _ = j
}
