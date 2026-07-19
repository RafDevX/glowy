package main

import "fmt"

type clearance int

func main() {
	// glowy::label::{private}
	classified := clearance(7)

	// glowy::label::{secret}
	revealClearance := true

	var selected any = "guest"

	if revealClearance {
		selected = classified
	}

	clearanceValue, ok := selected.(clearance)

	// glowy::assert::{private, secret}
	fmt.Println(clearanceValue)

	// glowy::assert::{secret}
	fmt.Println(ok)
}
