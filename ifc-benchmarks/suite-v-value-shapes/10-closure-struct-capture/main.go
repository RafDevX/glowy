package main

import "fmt"

type Options struct {
	Tag   int
	Count int
}

func main() {
	// glowy::label::{high}
	const secret = 42

	options := Options{Tag: secret}
	readTag := func() int {
		return options.Tag
	}

	options.Count = 1

	// glowy::assert::{high}
	fmt.Println(readTag())

	// glowy::assert::{}
	fmt.Println(options.Count)
}
