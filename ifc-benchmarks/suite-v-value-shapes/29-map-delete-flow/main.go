package main

import "fmt"

func main() {
	// glowy::label::{value}
	secretValue := 11
	// glowy::label::{key}
	secretKey := 0
	// glowy::label::{condition}
	remove := true

	values := map[int]int{0: secretValue}

	if remove {
		delete(values, secretKey)
	}

	value, ok := values[0]

	// glowy::assert::{value, key, condition}
	fmt.Println(value)
	// glowy::assert::{key, condition}
	fmt.Println(ok)
}
