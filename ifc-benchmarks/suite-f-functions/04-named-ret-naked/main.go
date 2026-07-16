package main

import "fmt"

// glowy::label::{private}
const private = "..."

func classify(input string) (flag string) {
	flag = input + private

	return
}

func main() {
	// glowy::label::{high}
	const secret = "top"

	classified := classify(secret)

	// glowy::assert::{high, private}
	fmt.Println(classified)
}
