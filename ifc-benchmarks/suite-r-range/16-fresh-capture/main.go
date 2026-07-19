package main

import "fmt"

// glowy::label::{red}
const red = 10

// glowy::label::{blue}
const blue = 20

func main() {
	var firstRead, secondRead func() int

	for iteration := range 2 {
		if iteration == 0 {
			iteration = red

			firstRead = func() int { return iteration }
		} else {
			iteration = blue

			secondRead = func() int { return iteration }
		}
	}

	// glowy::assert::{red}
	fmt.Println(firstRead())

	// glowy::assert::{blue}
	fmt.Println(secondRead())
}
