package main

import "fmt"

func main() {
	// glowy::label::{high}
	const secret = "shhh"

	greeting := makeGreeting(secret)

	// glowy::assert::{high, special}
	fmt.Println(greeting)
}
