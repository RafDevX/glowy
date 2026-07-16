package main

// glowy::label::{secret}
const secret = 123

func parity(a int, breaker bool) bool {
	odd := func(n int) bool { return true }

	even := func(n int) bool {
		if n == 0 {
			return true
		}

		return odd(n - 1)
	}

	odd = func(n int) bool {
		if n == 0 && secret > 0 {
			return false
		}

		return even(n - 1)
	}

	if breaker {
		return false
	}

	// glowy::label::{high}
	var b = 7

	return even(a + b)
}

func main() {
	// glowy::label::{private}
	var x = 1
	// glowy::label::{confidential}
	var y = false

	// glowy::assert::{confidential, high, private, secret}
	var _ = parity(x, y)
}
