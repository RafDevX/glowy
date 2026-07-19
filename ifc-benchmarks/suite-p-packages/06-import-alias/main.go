package main

import "fmt"

func main() {
	earthCode := earthSecret()
	marsCode := marsSecret()

	// glowy::assert::{earth}
	fmt.Println(earthCode)
	// glowy::assert::{mars}
	fmt.Println(marsCode)
}
