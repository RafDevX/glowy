package main

import "fmt"

func main() {
	// glowy::label::{high}
	limit := 5

	total := 0
	for i := range limit {
		total += i
	}

	// glowy::assert::{high}
	fmt.Println(total)
}
