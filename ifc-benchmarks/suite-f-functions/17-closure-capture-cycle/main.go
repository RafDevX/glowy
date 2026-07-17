package main

// glowy::label::{secret}
const secret = 1

func main() {
	x := secret
	var y int

	f := func() int {
		defer func() { y = 0 }()

		if y > 0 {
			x = y
		}

		if x > 0 {
			return x
		}

		return x
	}

	// glowy::assert::{secret}
	var _ = f()
}
