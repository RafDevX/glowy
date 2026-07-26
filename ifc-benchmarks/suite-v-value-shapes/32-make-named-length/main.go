package main

import "fmt"

func main() {
	length := 1
	values := make([]int, length)

	// glowy::label::{high}
	secret := 42
	values = append(values, secret)

	// glowy::assert::{}
	fmt.Println(values[0])

	// glowy::assert::{high}
	fmt.Println(values[1])
}
