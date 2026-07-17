package main

import "fmt"

// glowy::label::{alice}
const alice = 5

// glowy::label::{bob}
const bob = 4

func main() {
	value := alice

	outerRead := func() int { return value }

	var innerRead func() int

	{
		value := bob

		innerRead = func() int { return value }
	}

	// glowy::assert::{alice}
	fmt.Println(outerRead())

	// glowy::assert::{bob}
	fmt.Println(innerRead())
}
