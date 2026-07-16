package main

func main() {
	const zero = 0

	// glowy::label::{one}
	const one = 1

	// glowy::label::{two}
	const two = one + 1

	addTwo(zero)
	addTwo(one)
	addTwo(two)
}

func addTwo(n int) {
	addOne(n + 1)
}

func addOne(n int) {
	observe(n + 1)
}

func observe(n int) {
	// glowy::assert::{->, one, ->, one, two}
	var _ = n + 1
}
