package main

import "fmt"

func pair() (int, int) { return 1, 2 }

func main() {
	first, second := pair()

	// glowy::assert::{}
	fmt.Println(first)

	// glowy::assert::{secret}
	fmt.Println(second)
}
