package main

import "fmt"

func main() {
	// glowy::label::{secret}
	chooseTypedNil := true

	var selected any

	if chooseTypedNil {
		var absent []int

		selected = absent
	}

	observedNil := selected == nil

	// glowy::assert::{secret}
	fmt.Println(observedNil)
}
