package main

func factory(seed int) func(int) int {
	// glowy::label::{private}
	var private = 3

	return func(x int) int { return seed + private + x }
}

func main() {
	// glowy::label::{alice}
	var alice = 2

	// glowy::label::{bob}
	var bob = 5

	var op = factory(alice)

	// glowy::assert::{alice, bob, private}
	var _ = op(bob)
}
