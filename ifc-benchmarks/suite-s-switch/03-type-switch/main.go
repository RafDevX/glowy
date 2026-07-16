package main

func main() {
	// glowy::label::{a}
	a := 0
	// glowy::label::{b}
	b := 0
	// glowy::label::{c}
	c := 0

	// glowy::label::{high}
	high := 7

	discriminant := func(x interface{}) {
		switch shadow := high; y := x.(type) {
		case nil:
			a += 2
		case int, string:
			b += 4
		case float64:
			b += int(y)
		default:
			c += shadow
		}
	}

	// glowy::label::{x}
	x := 2
	// glowy::label::{y}
	y := "hello"
	// glowy::label::{z}
	z := func() int {
		// glowy::label::{inner}
		inner := 9

		return 9 * inner
	}

	discriminant(x)

	// glowy::assert::{a, x}
	var _ = a
	// glowy::assert::{b, x}
	var _ = b
	// glowy::assert::{c, x, high}
	var _ = c

	discriminant(y)
	discriminant(z)

	// glowy::assert::{a, x, y, z}
	var _ = a
	// glowy::assert::{b, x, y, z}
	var _ = b
	// glowy::assert::{c, x, y, z, high}
	var _ = c
}
