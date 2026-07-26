package main

import "fmt"

// glowy::label::{alpha}
const alpha = 1

// glowy::label::{beta}
const beta = 2

func main() {
	m := map[int]int{}
	m[1] = alpha

	closure := func() {
		m[2] = beta
	}

	closure()

	// glowy::assert::{alpha}
	fmt.Println(m[1])

	// glowy::assert::{beta}
	fmt.Println(m[2])
}
