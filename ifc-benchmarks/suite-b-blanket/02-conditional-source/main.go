package main

import "fmt"

func text(value string) string { return value }

func number(value int) int { return value }

func boolean(value bool) bool { return value }

func main() {
	// glowy::assert::{}
	fmt.Println(text("public"))

	// glowy::assert::{exact}
	fmt.Println(text("SECRET"))

	// glowy::assert::{fuzzy}
	fmt.Println(text("api-" + "token"))

	// glowy::assert::{}
	fmt.Println(number(4))

	// glowy::assert::{integer}
	fmt.Println(number(2 + 3))

	// glowy::assert::{}
	fmt.Println(boolean(1 > 2))

	// glowy::assert::{boolean}
	fmt.Println(boolean(1 < 2))

	publicText := "public"

	// glowy::assert::{}
	fmt.Println(text(publicText))

	exactText := "SECRET"

	// glowy::assert::{exact}
	fmt.Println(text(exactText))

	publicNumber := 4

	// glowy::assert::{}
	fmt.Println(number(publicNumber))

	matchingNumber := 2 + 3

	// glowy::assert::{integer}
	fmt.Println(number(matchingNumber))
}
