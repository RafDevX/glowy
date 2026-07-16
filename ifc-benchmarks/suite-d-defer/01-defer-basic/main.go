package main

import "fmt"

func main() {
	// glowy::label::{high}
	var secret = 42

	defer observe(secret)
}

func observe(a int) {
	// glowy::assert::{high}
	fmt.Println(a)
}
