package main

import "fmt"

func main() {
	// glowy::label::{red}
	redSource := "internal"

	// glowy::label::{blue}
	blueSource := "restricted"

	current := redSource

	current, previous := blueSource, current

	// glowy::assert::{blue}
	fmt.Println(current)

	// glowy::assert::{red}
	fmt.Println(previous)
}
