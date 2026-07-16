package main

import "fmt"

// glowy::label::{doubler}
const doubler = 2

// glowy::label::{tax}
const tax = 1

func composer(outer func(int) int, inner func(int) int) func(int) int {
	return func(n int) int {
		return outer(inner(n))
	}
}

func main() {
	f := func(n int) int { return doubler * n }

	composed := composer(
		func(n int) int { return n + tax },
		f,
	)

	// glowy::label::{seven}
	seven := 7

	// glowy::label::{nine}
	nine := 9

	// glowy::assert::{seven, doubler}
	fmt.Println(f(seven))

	// glowy::assert::{nine, doubler, tax}
	fmt.Println(composed(nine))
}
