package main

import "fmt"

// glowy::label::{red}
var report = "internal"

// glowy::label::{blue}
var blue = "restricted"

func rewrite(report string) string {
	// glowy::assert::{}
	fmt.Println(report)

	report = blue

	return report
}

func main() {
	rewritten := rewrite("public")

	// glowy::assert::{blue}
	fmt.Println(rewritten)

	// glowy::assert::{red}
	fmt.Println(report)
}
