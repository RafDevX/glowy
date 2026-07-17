package main

import "fmt"

func main() {
	var clear = 0

	// glowy::label::{high}
	var secret = 1 + clear

	var negated = (-secret) + 3

	// glowy::label::{red}
	red := 4
	// glowy::label::{blue}
	blue := 7

	minimum := min(red, blue)
	maximum := max(red, blue)

	// glowy::assert::{}
	fmt.Println(clear)
	// glowy::assert::{high}
	fmt.Println(secret, negated)
	// glowy::assert::{red, blue}
	fmt.Println(minimum, maximum)
}
