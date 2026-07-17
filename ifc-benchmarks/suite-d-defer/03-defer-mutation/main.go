package main

import "fmt"

func main() {
	// glowy::label::{high}
	var secret = 42

	state := 0

	defer func() {
		// glowy::assert::{high}
		fmt.Println(state)
	}()

	defer func() { state = secret }()
}
