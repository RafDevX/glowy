package main

import "fmt"

func main() {
	// glowy::label::{value}
	secretValue := 17
	// glowy::label::{condition}
	remove := true

	values := map[int]int{0: secretValue}

	if remove {
		clear(values)
	}

	value, ok := values[0]

	// glowy::assert::{value, condition}
	fmt.Println(value)
	// glowy::assert::{condition}
	fmt.Println(ok)
}
