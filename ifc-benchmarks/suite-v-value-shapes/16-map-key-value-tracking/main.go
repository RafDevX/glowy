package main

import "fmt"

const inc = 1

func main() {
	// glowy::label::{high}
	secret := 42

	values := map[int]int{1: secret, 2: 0}
	key := 1

	// glowy::assert::{high}
	fmt.Println(values[key])

	key = 1 + inc

	// glowy::assert::{}
	fmt.Println(values[key])

	copy := key

	// glowy::assert::{}
	fmt.Println(values[copy])

	var condition bool
	if condition {
		copy = 1
	}

	// glowy::assert::{high}
	fmt.Println(values[copy])

	closureKey := 1
	setClosureKey := func() {
		closureKey = 2
	}
	setClosureKey()

	// glowy::assert::{}
	fmt.Println(values[closureKey])

	conditionalClosureKey := 2
	setConditionalClosureKey := func() {
		conditionalClosureKey = 1
	}
	if condition {
		setConditionalClosureKey()
	}

	// glowy::assert::{high}
	fmt.Println(values[conditionalClosureKey])
}
