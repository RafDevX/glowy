package main

// glowy::label::{bob}
const bob = 1

func main() {
	// glowy::label::{initial}
	var delta = 1

	current := func() int { return bob + delta }

	combine := func() int {
		a := current()

		// glowy::label::{middle}
		delta = 2

		b := current()

		// glowy::label::{final}
		delta = 3

		c := current()

		return a + b + c
	}

	// glowy::label::{entry}
	delta = 4

	// glowy::assert::{bob, entry, middle, final}
	var _ = combine()
}
