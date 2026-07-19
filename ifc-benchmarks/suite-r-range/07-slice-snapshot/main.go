package main

import "fmt"

func main() {
	// glowy::label::{secret}
	const secret = 1

	values := []int{0, 0}
	observed := 0

	for index, value := range values {
		if index == 0 {
			values[1] = secret
		}

		observed = value
	}

	// glowy::assert::{secret}
	fmt.Println(observed)
}
