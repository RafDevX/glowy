package main

import "fmt"

// glowy::label::{secret}
const secret = true

func main() {
	iters := 0
	result := 0

	for {
		iters++
		if iters == 1 && secret {
			continue
		}

		result = iters
		break
	}

	// glowy::assert::{secret}
	fmt.Println(iters, result)
}
