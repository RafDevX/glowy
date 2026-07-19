package main

import "fmt"

type MySlice []int

func main() {
	// glowy::label::{high}
	const secret = 7

	raw := []int{1, secret, 3}
	s := MySlice(raw)

	// glowy::assert::{high}
	fmt.Println(s[1])

	// glowy::assert::{}
	fmt.Println(s[2])
}
