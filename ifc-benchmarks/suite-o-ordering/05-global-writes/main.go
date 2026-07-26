package main

// glowy::label::{blue}
const blue = 2

// glowy::label::{red}
const red = 9

var state int = 3

func definedBeforeCalledAfter() {
	state = blue
}

func definedAfterCalledBefore() {
	state = red
}

func main() {
	// glowy::assert::{}
	var _ = state

	definedAfterCalledBefore()

	// glowy::assert::{red}
	var _ = state

	definedBeforeCalledAfter()

	// glowy::assert::{blue}
	var _ = state
}
