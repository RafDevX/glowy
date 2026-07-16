package main

// glowy::label::{alice}
const alice = 5

// glowy::label::{bob}
const bob = 4

func main() {
	current := func() int { return alice }

	read := func() int { return current() + 1 }

	current = func() int { return bob }

	// glowy::assert::{bob}
	var _ = read()
}
