package main

import "fmt"

func main() {
	// glowy::label::{secret}
	const secret = 1

	values := [2]int{0, secret}
	observed := 0

	for index, value := range values {
		if index == 0 {
			values[1] = 0
		}

		observed = value
	}

	// glowy::assert::{secret}
	fmt.Println(observed)
}
