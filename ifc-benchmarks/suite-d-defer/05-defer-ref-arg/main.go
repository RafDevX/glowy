package main

import "fmt"

func main() {
	// glowy::label::{high}
	var secret = 42

	value := 0
	defer observe(&value)

	value = secret
}

func observe(value *int) {
	// glowy::assert::{high}
	fmt.Println(*value)
}
