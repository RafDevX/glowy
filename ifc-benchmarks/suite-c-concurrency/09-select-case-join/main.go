package main

import "fmt"

// glowy::label::{red}
const red = 1

// glowy::label::{blue}
const blue = 2

func main() {
	mars := make(chan struct{}, 1)
	venus := make(chan struct{}, 1)

	mars <- struct{}{}
	venus <- struct{}{}

	selected := 0
	select {
	case <-mars:
		selected = red
	case <-venus:
		selected = blue
	}

	// glowy::assert::{red, blue}
	fmt.Println(selected)
}
