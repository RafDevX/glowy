package main

// glowy::label::{blue}
const blue = 2

// glowy::label::{red}
const red = 9

var state int = blue

func main() {
	// glowy::assert::{red}
	var _ = state + 2
}

func init() {
	state = red
}
