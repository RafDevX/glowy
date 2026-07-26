package main

import "fmt"

func main() {
	// glowy::label::{length}
	length := 1

	source := make([]int, length)
	destination := make([]int, 2)
	copied := copy(destination, source)

	// glowy::assert::{length}
	fmt.Println(copied)
}
