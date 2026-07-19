package main

// glowy::label::{red}
const red = 1

// glowy::label::{blue}
const blue = 2

var current int

func replace() int {
	current = blue

	return 0
}

func observe() int { return current }

func main() {
	current = red
	after := replace() + observe()

	// glowy::assert::{blue}
	var _ = after

	current = red
	before := observe() + replace()

	// glowy::assert::{red}
	var _ = before
}
