package main

import "fmt"

func main() {
	// glowy::label::{left}
	left := 1
	// glowy::label::{right}
	right := 3

	values := []int{left, 0, right}
	low := 1
	high := 2

	// glowy::assert::{}
	fmt.Println(values[low:high])
}
