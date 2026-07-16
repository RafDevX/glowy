package main

import "fmt"

func main() {
	var clear = 0

	// glowy::label::{high}
	var secret = 1 + clear

	var negated = (-secret) + 3

	// glowy::assert::{}
	fmt.Println(clear)
	// glowy::assert::{high}
	fmt.Println(secret)
	// glowy::assert::{high}
	fmt.Println(negated)
}
