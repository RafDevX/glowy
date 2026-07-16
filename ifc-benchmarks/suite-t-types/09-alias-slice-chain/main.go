package main

import "fmt"

type Inner []int
type Middle Inner
type Outer = Middle

func main() {
	// glowy::label::{high}
	const value = 42

	outer := make(Outer, 0)
	outer = append(outer, value)

	// glowy::assert::{high}
	fmt.Println(outer[0])
}
