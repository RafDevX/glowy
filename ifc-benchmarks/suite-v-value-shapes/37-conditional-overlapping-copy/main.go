package main

import "fmt"

func main() {
	// glowy::label::{condition}
	condition := true
	// glowy::label::{red}
	red := 1
	// glowy::label::{blue}
	blue := 2

	values := []int{red, blue, 0}

	if condition {
		copy(values[1:], values[:2])
	}

	// glowy::assert::{red}
	fmt.Println(values[0])
	// glowy::assert::{condition, red, blue}
	fmt.Println(values[1])
	// glowy::assert::{condition, blue}
	fmt.Println(values[2])
}
