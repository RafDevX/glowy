package main

import "fmt"

// glowy::label::{high}
const high = true

func main() {
	completed := 0

Outer:
	for outer := 0; outer < 2; outer++ {
		for {
			if high {
				break Outer
			}
			break
		}

		completed++
	}

	// glowy::assert::{high}
	fmt.Println(completed)
}
