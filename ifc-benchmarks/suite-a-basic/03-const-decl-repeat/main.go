package main

// glowy::label::{secret}
const secret = 7

// glowy::label::{high}
const high = 3

const (
	Sun = iota
	Mon
	Tue
	Wed = secret
	Thu = iota
	Fri
	Sat
	numberOfDays
)

const (
	ant float64 = 4.3
	bear
	cow = 8
	dromedary
	elephant = high
	frog
	giraffe
	hyena = iota
	iguana
)

func main() {
	// glowy::assert::{}
	var _, _, _, _, _, _ = Sun, Mon, Tue, Thu, Fri, numberOfDays

	// glowy::assert::{secret}
	var _ = Wed

	// glowy::assert::{}
	var _, _, _, _, _, _ = ant, bear, cow, dromedary, hyena, iguana

	// glowy::assert::{high}
	var _, _, _ = elephant, frog, giraffe
}
