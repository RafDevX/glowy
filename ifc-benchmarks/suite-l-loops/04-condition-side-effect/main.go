package main

import "fmt"

func exfiltrate(n int) bool {
	// glowy::assert::{high}
	fmt.Println(n)

	return true
}

func main() {
	// glowy::label::{high}
	var high = 2

	for i := 0; exfiltrate(i); i = high {
		if i > 0 {
			break
		}
	}
}
