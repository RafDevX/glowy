package main

import "fmt"

// glowy::label::{high}
const high = 3.9

func main() {
	result := f0()

	// glowy::assert::{high}
	fmt.Println(result)
}

func f0() float64 { return f1() }
func f1() float64 { return f2() }
func f2() float64 { return f3() }
func f3() float64 { return high }
