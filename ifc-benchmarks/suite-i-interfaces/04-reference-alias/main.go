package main

import "fmt"

// glowy::label::{secret}
const secret = 7

func main() {
	readings := []int{secret, 2}

	var boxed any = readings
	copied := boxed

	// glowy::label::{private}
	classified := 42

	readings[0] = classified

	recovered := copied.([]int)

	// glowy::assert::{private}
	fmt.Println(recovered[0])
}
