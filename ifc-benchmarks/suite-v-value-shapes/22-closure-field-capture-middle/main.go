package main

type box struct {
	value int
}

// glowy::label::{bob}
const bob = 1

func main() {
	state := box{value: bob}

	current := func() int { return state.value }

	combine := func() int {
		a := current()

		// glowy::label::{middle}
		state.value = 2

		b := current()

		// glowy::label::{final}
		state.value = 3

		c := current()

		return a + b + c
	}

	// glowy::assert::{bob, middle, final}
	var _ = combine()
}
