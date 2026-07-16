package main

// glowy::label::{confidential}
const text = "Hello"

// glowy::label::{secret}
const prime = 7

func main() {
	// glowy::label::{red}
	red := 4
	// glowy::label::{blue}
	blue := 2
	// glowy::label::{green}
	green := 7

	result := matchesTotal(text, prime, red, blue, 9*red, -red, green, 2)

	// glowy::assert::{red, blue, green}
	var _ = result

	together := []int{blue, 6, green}

	// glowy::assert::{blue, green}
	var _ = matchesTotal("Take 2", red, 4, together...)
}

func matchesTotal(label string, a, b int, others ...int) bool {
	var _ = a

	total := 0

	_ = label
	a = 2

	for i, num := range others {
		total += i * num
	}

	return (a + b) == total
}
