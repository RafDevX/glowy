package main

import "fmt"

func enrich(input int) int {
	carried := input

	// glowy::label::{red, blue}
	modifier := 3
	mixed := carried + modifier

	// glowy::label::{blue, green}
	bonus := 5

	// glowy::label::{unused}
	ignored := 5.4

	return finish(mixed, bonus, ignored)
}

func finish(value int, bonus int, _ float64) int {
	// glowy::label::{red, orange}
	local := 1

	return value + bonus + local
}

func main() {
	// glowy::label::{yellow}
	start := 1

	result := enrich(start)

	// glowy::assert::{red, blue, green, yellow, orange}
	fmt.Println(result)
}
