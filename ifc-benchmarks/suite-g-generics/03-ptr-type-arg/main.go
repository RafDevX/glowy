package main

import "fmt"

type Record struct{ value int }

func MakeOne[T any](v T) T {
	return v
}

func main() {
	// glowy::label::{secret}
	tainted := &Record{value: 1}

	out := MakeOne[*Record](tainted)

	// glowy::assert::{secret}
	fmt.Println(out)
}
