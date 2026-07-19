package main

import "fmt"

func main() {
	// glowy::label::{secret}
	const secret = "hidden"

	credential := [1]string{secret}
	matches := credential == [1]string{"public"}

	// glowy::assert::{secret}
	fmt.Println(matches)
}
