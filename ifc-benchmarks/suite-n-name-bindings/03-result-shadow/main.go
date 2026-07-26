package main

import "fmt"

func preserve(value string) (result string) {
	result = value

	{
		result := "public"

		// glowy::assert::{}
		fmt.Println(result)
	}

	return
}

func main() {
	// glowy::label::{secret}
	secret := "hidden"

	result := preserve(secret)

	// glowy::assert::{secret}
	fmt.Println(result)
}
