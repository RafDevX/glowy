package main

import "fmt"

func main() {
	// glowy::label::{high}
	secretHigh := 7

	sources := []int{0, secretHigh}

	values := []int{0, 0}
	position := 0

	advance := func() int { position = 1; return 0 }
	current := func() int { return position }

	observed := 0

	values[advance()], values[current()], observed = 0, secretHigh, sources[current()]

	// glowy::assert::{}
	fmt.Println(values[0])

	// glowy::assert::{high}
	fmt.Println(values[1], observed)
}
