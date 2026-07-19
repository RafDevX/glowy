package main

import "fmt"

// glowy::label::{secret}
const secret = "hidden"

func main() {
	mars := make(chan string, 1)
	venus := make(chan string, 1)

	select {
	case mars <- secret:
	case venus <- secret:
	}

	var received string
	select {
	case received = <-mars:
	case received = <-venus:
	}

	// glowy::assert::{secret}
	fmt.Println(received)
}
