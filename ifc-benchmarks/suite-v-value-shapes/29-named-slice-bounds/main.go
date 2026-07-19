package main

import "fmt"

func main() {
	// glowy::label::{left}
	left := 1
	// glowy::label::{right}
	right := 3

	values := []int{left, 0, right, 0}

	// glowy::label::{lower}
	low := 1
	// glowy::label::{upper}
	high := 2
	// glowy::label::{maximum}
	max := 3

	view := values[low:high:max]
	first := view[0]
	last := view[len(view)-1]

	// glowy::assert::{lower, left, right}
	fmt.Println(first)
	// glowy::assert::{upper, left, right}
	fmt.Println(last)
	// glowy::assert::{lower, upper}
	fmt.Println(len(view))
	// glowy::assert::{lower, maximum}
	fmt.Println(cap(view))

	// glowy::label::{private}
	appended := 7
	_ = append(view, appended)

	// glowy::assert::{right, private, upper, maximum}
	fmt.Println(values[2])
}
