package main

import "fmt"

func main() {
	// glowy::label::{red}
	red := 1
	// glowy::label::{blue}
	blue := 2

	values := []int{red, blue, 0}
	copy(values[1:], values[:2])

	// glowy::assert::{red}
	fmt.Println(values[0], values[1])
	// glowy::assert::{blue}
	fmt.Println(values[2])
}
