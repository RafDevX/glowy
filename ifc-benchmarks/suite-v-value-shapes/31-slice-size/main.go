package main

import "fmt"

func main() {
	// glowy::label::{slice-length}
	length := 1

	// glowy::label::{slice-capacity}
	capacity := 2

	values := make([]int, length, capacity)

	// glowy::assert::{slice-length}
	fmt.Println(len(values))

	// glowy::assert::{slice-capacity}
	fmt.Println(cap(values))
}
