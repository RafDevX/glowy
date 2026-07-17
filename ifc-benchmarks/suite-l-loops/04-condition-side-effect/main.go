package main

import "fmt"

var lastCheck int

func exfiltrate(n int) bool {
	lastCheck = n

	// glowy::assert::{high}
	fmt.Println(n)

	return n < 2
}

func main() {
	// glowy::label::{high}
	var high = 2

	for i := 0; exfiltrate(i); {
		i = high
	}

	// glowy::assert::{high}
	fmt.Println(lastCheck)
}
