package main

import "fmt"

func main() {
	// glowy::label::{red}
	red := 3
	// glowy::label::{blue}
	blue := 0
	// glowy::label::{green}
	green := 3

	result := 0
	switch {
	case blue > red:
		result = blue
	case green > red:
		result = green
	default:
		output()
		result = 0
	}

	// glowy::assert::{red}
	var _ = red
	// glowy::assert::{blue}
	var _ = blue
	// glowy::assert::{green}
	var _ = green
	// glowy::assert::{red, blue, green}
	var _ = result
}

func output() {
	// glowy::assert::{red, blue, green}
	fmt.Println(0)
}
