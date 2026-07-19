package main

import "fmt"

func main() {
	// glowy::label::{high}
	secretHigh := 10

	// glowy::label::{private}
	secretPrivate := 1

	values := []int{secretHigh}

	values[0] += secretPrivate

	// glowy::assert::{high, private}
	fmt.Println(values[0])

	// glowy::label::{key}
	secretKey := "red"

	counts := map[string]int{"red": 0, "blue": 0}

	counts[secretKey]++

	// glowy::assert::{key}
	fmt.Println(counts["red"], counts["blue"])
}
