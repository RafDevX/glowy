package main

import "fmt"

func main() {
	// glowy::label::{high}
	const secret = 42

	b := byte(secret)

	// glowy::assert::{high}
	fmt.Println(b)
}
