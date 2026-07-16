package main

import "fmt"

func main() {
	// glowy::label::{red}
	redSource := 1

	value := redSource

	// glowy::assert::{red}
	fmt.Println(value)

	value = 0

	// glowy::assert::{}
	fmt.Println(value)

	// glowy::label::{blue}
	blueSource := 2

	guarded := 0
	if redSource > 0 {
		guarded = blueSource
	} else {
		guarded = 0
	}

	// glowy::assert::{red, blue}
	fmt.Println(guarded)

	preserved := blueSource
	if redSource > 0 {
		preserved = 0
	}

	// glowy::assert::{red, blue}
	fmt.Println(preserved)
}
