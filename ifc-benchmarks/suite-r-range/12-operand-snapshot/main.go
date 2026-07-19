package main

import "fmt"

// glowy::label::{red}
const red = 1

// glowy::label::{blue}
const blue = 2

var next = red

func values() []int {
	current := next
	next = blue

	return []int{current, current}
}

func main() {
	total := 0

	for _, value := range values() {
		total += value
	}

	// glowy::assert::{red}
	fmt.Println(total)

	// glowy::assert::{blue}
	fmt.Println(next)
}
