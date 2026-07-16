package main

import "fmt"

const secretIndex = 2

func main() {
	// glowy::label::{high}
	secret := 42

	values := []int{0, secretIndex: secret}

	// glowy::assert::{}
	fmt.Println(values[0])

	// glowy::assert::{high}
	fmt.Println(values[secretIndex])
}
