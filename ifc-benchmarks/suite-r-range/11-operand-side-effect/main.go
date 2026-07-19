package main

import "fmt"

// glowy::label::{secret}
const secret = 1

var observed int

func emptyValues() []int {
	observed = secret

	return []int{}
}

func main() {
	for range emptyValues() {
	}

	// glowy::assert::{secret}
	fmt.Println(observed)
}
