package main

import "fmt"

func main() {
	// glowy::label::{secret}
	var x = 42

	// glowy::label::{initial}
	var y = 12

	defer (build(y))(x)

	x = 7

	// glowy::label::{high}
	y = 0

	// glowy::assert::{}
	fmt.Println(x)

	// glowy::assert::{high}
	fmt.Println(y)
}

func observe(a int) {
	// glowy::assert::{initial, secret}
	fmt.Println(a)
}

func build(a int) func(int) {
	// glowy::assert::{initial}
	fmt.Println(a)

	return func(b int) { observe(a + b) }
}
