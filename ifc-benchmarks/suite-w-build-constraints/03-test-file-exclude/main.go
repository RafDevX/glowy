package main

import "fmt"

func main() {
	// glowy::label::{high}
	const secret = "hush"

	out := transform(secret)

	// glowy::assert::{high}
	fmt.Println(out)
}

func transform(s string) string {
	return "real: " + s
}
