package main

import "fmt"

// glowy::label::{leaky}
const leaky = 7

func main() {
	s := []int{leaky, 2, 3, 4, 5}

	for i := range len(s) {
		// glowy::assert::{}
		fmt.Println(i)

		// glowy::assert::{leaky}
		fmt.Println(s[i])
	}
}
