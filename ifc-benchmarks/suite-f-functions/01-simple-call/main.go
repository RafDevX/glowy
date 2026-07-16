package main

import "fmt"

func main() {
	public := 0
	first := combine(public, 5)
	observe(first)

	// glowy::label::{high}
	secret := 4
	second := combine(secret, first)
	observe(second)
}

func combine(left int, right int) int {
	return left + right
}

func observe(value int) {
	// glowy::assert::{->, high}
	fmt.Println(value)
}
