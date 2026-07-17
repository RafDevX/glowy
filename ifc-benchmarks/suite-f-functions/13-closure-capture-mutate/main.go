package main

// glowy::label::{alice}
const alice = 5

// glowy::label::{bob}
const bob = 4

// glowy::label::{charlie}
const charlie = 2

// glowy::label::{david}
const david = 7

// glowy::label::{eve}
const eve = 0

var mutable = charlie

func main() {
	// glowy::label::{one}
	var delta = 1

	current := func() int { return alice + delta }

	// glowy::label::{two}
	delta = 2

	combine := func() int {
		before := current()

		// glowy::label::{five}
		five := 5

		delta = mutable + five

		return before + current() + 1
	}

	// glowy::label::{three}
	delta = 3

	current = func() int { return bob + delta }

	// glowy::label::{four}
	delta = 4

	mutable = david

	// glowy::assert::{bob, four, david, five}
	var _ = combine()

	// glowy::assert::{david, five}
	var _ = delta

	delta = eve

	// glowy::assert::{eve}
	var _ = delta
}
