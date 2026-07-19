package main

import "fmt"

func main() {
	// glowy::label::{high}
	payload := 42

	// glowy::label::{private}
	privateChoice := true

	result := revise(payload, privateChoice)

	// glowy::assert::{high, private}
	fmt.Println(result)
}

func revise(payload int, privateChoice bool) (result int) {
	defer func() {
		// glowy::assert::{high}
		fmt.Println(result)

		if privateChoice {
			result++
		}
	}()

	return payload
}
