package main

import "fmt"

func main() {
	// glowy::label::{secret}
	secretIndex := 1
	// glowy::label::{private}
	secretValue := 30

	array := [...]int{10, 20}
	slice := []int{10, 20}
	text := "ab"
	mapping := map[int]string{0: "zero", 1: "one"}

	// glowy::assert::{}
	fmt.Println(array[0], slice[0], text[0], mapping[0])

	value, ok := mapping[secretIndex]

	// glowy::assert::{secret}
	fmt.Println(array[secretIndex], slice[secretIndex], text[secretIndex], value, ok)

	array[secretIndex] = secretValue
	slice[secretIndex] = secretValue

	// glowy::assert::{secret, private}
	fmt.Println(array[0], array[1], slice[0], slice[1])

	// glowy::label::{membership}
	includeValue := true
	conditional := map[int]int{}
	if includeValue {
		conditional[0] = 1
	}

	conditionalValue, conditionalOk := conditional[0]
	withoutOk, _ := conditional[0]

	// glowy::assert::{membership}
	fmt.Println(conditionalValue, conditionalOk, withoutOk)
}
