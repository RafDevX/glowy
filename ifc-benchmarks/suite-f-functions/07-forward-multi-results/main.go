package main

import "fmt"

// glowy::label::{high}
const secret = "alpha"

func inner(s string) (string, int) {
	return "length is", len(s)
}

func wrap() (string, int) {
	return inner(secret)
}

func main() {
	s, n := wrap()

	// glowy::assert::{}
	fmt.Println(s)

	// glowy::assert::{high}
	fmt.Println(n)
}
