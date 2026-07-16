package main

import "fmt"

func main() {
	var public = 0

	// glowy::label::{high}
	var guard = 1 + public
	var choice = 0
	var result = choice

	// glowy::assert::{}
	fmt.Println(result + choice)

	if guard == 1 {
		choice = 1
	} else {
		choice = 2
	}

	if public == 0 {
		result = choice
	} else {
		result = public
	}

	// glowy::assert::{}
	fmt.Println(public)
	// glowy::assert::{high}
	fmt.Println(guard, choice, result)
}
