package main

// glowy::label::{secret}
const secret = 7

func main() {
	ret := 100
	f := func() int { return ret }
	g := func() int { return f() }
	h := func() int { return g() }

	var recurs func(int) int

	recurs = func(n int) int {
		ret = secret

		if n < h() {
			return 1 + recurs(n+1)
		} else {
			return 0
		}
	}

	// glowy::assert::{secret}
	var _ = 3 + recurs(3)
}
