package main

// glowy::label::{secret}
const secret = 1

func main() {
	var delta = secret

	f := func() int { return delta }
	g := func() int { return f() }
	h := func() int { return g() }

	outer := func() int {
		_ = f
		_ = g
		_ = delta
		return h()
	}

	// glowy::assert::{secret}
	var _ = outer()
}
