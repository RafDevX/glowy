package main

import (
	"fmt"

	"qualified-conversion/innertypes"
)

func main() {
	// glowy::label::{high}
	const secret = 42

	u := innertypes.UserID(secret)

	// glowy::assert::{high}
	fmt.Println(u)
}
