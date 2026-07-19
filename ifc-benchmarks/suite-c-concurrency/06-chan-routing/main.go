package main

import "fmt"

func main() {
	// glowy::label::{route}
	useMars := true

	mars := make(chan string, 1)
	venus := make(chan string, 1)

	mars <- "Mars"
	venus <- "Venus"

	routes := make(chan chan string, 1)

	if useMars {
		routes <- mars
	} else {
		routes <- venus
	}

	selected := <-routes
	planet := <-selected

	// glowy::assert::{route}
	fmt.Println(planet)
}
