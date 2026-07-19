package main

import "fmt"

// glowy::label::{red}
const red = 10

// glowy::label::{blue}
const blue = 20

func main() {
	var iteration int

	observations := make(chan int)

	for iteration = range 2 {
		if iteration == 0 {
			iteration = red

			go func() { observations <- iteration }()
		} else {
			iteration = blue
		}
	}

	// glowy::assert::{red, blue}
	fmt.Println(<-observations)
}
