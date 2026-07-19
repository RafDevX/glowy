package main

import "fmt"

// glowy::label::{secret}
const secret = true

func main() {
	completed := 0

Outer:
	for outer := 0; outer < 2; outer++ {
		for {
			if secret {
				continue Outer
			}
			break
		}
		completed++
	}

	// glowy::assert::{secret}
	fmt.Println(completed)
}
