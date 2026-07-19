package main

// glowy::label::{secret}
const secret = 1

func main() {
	m := map[int]int{0: secret}

	current := func() int { return m[0] }

	combine := func() int {
		a := current()

		// glowy::label::{middle}
		m[0] = 2

		b := current()

		// glowy::label::{final}
		m[0] = 3

		c := current()

		return a + b + c
	}

	// glowy::assert::{secret, middle, final}
	var _ = combine()
}
