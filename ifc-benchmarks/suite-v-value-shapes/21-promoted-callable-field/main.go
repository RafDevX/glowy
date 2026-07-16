package main

import "fmt"

type Inner struct {
	Hook func(string) string `glowy:"high"`
}

type Outer struct {
	Inner
}

func main() {
	outer := Outer{
		Inner: Inner{
			Hook: func(s string) string { return "wrapped:" + s },
		},
	}

	wrapped := outer.Hook("payload")

	// glowy::assert::{high}
	fmt.Println(wrapped)
}
