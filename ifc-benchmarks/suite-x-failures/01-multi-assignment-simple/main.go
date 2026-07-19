package main

import "fmt"

func main() {
	// glowy::label::{high}
	secretHigh := 7

	values := []int{0, 0}
	position := 0

	position, values[position] = 1, secretHigh

	// glowy::assert::{high}
	fmt.Println(values[0])

	// glowy::assert::{}
	fmt.Println(values[1])
}
