package main

import "fmt"

type clearance int

func main() {
	// glowy::label::{private}
	classified := clearance(7)

	// glowy::label::{secret}
	revealClearance := true

	var selected any = 7

	if revealClearance {
		selected = classified
	}

	clearanceValue := selected.(clearance)

	// glowy::assert::{private, secret}
	fmt.Println(clearanceValue)
}
