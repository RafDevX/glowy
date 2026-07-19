package main

import "fmt"

func main() {
	// glowy::label::{route}
	useMars := true

	mars := make(chan struct{}, 1)
	venus := make(chan struct{}, 1)

	if useMars {
		mars <- struct{}{}
	} else {
		venus <- struct{}{}
	}

	planet := ""

	select {
	case <-mars:
		planet = "Mars"
	case <-venus:
		planet = "Venus"
	}

	// glowy::assert::{route}
	fmt.Println(planet)
}
