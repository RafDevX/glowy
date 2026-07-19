package main

import "fmt"

// glowy::label::{key}
const secretIndex = 2

func main() {
	// A keyed zero-value is still semantically present: it determines both the
	// next implicit index and the composite literal's length.
	values := []int{secretIndex: 0}

	// glowy::assert::{key}
	fmt.Println(len(values))

	// glowy::label::{value}
	secret := 42

	values = []int{2: 0, secret}

	// glowy::assert::{}
	fmt.Println(values[1])

	// glowy::assert::{value}
	fmt.Println(values[3])

	// The greatest index, rather than the final explicit index, determines the
	// length. The append must therefore write index 6, not index 2.
	values = []int{5: 0, 1: 0}
	values = append(values, secret)

	// glowy::assert::{}
	fmt.Println(values[2])

	// glowy::assert::{value}
	fmt.Println(values[6])
}
