package main

import "fmt"

func main() {
	// glowy::label::{high}
	secretHigh := 1

	// glowy::label::{private}
	secretPrivate := 2

	first, second, third := secretHigh, secretPrivate, 0

	first, second, third = second, third, first

	// glowy::assert::{private}
	fmt.Println(first)

	// glowy::assert::{}
	fmt.Println(second)

	// glowy::assert::{high}
	fmt.Println(third)

	first, first = secretHigh, secretPrivate

	// glowy::assert::{private}
	fmt.Println(first)
}
