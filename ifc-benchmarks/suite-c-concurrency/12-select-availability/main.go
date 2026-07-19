package main

import "fmt"

func main() {
	// glowy::label::{availability}
	enabled := true

	ready := make(chan struct{}, 1)
	ready <- struct{}{}

	var selected <-chan struct{}
	if enabled {
		selected = ready
	}

	available := false

	select {
	case <-selected:
		available = true
	default:
	}

	// glowy::assert::{availability}
	fmt.Println(available)
}
