package main

import "fmt"

type Classified struct {
	token string `glowy:"classified"`
}

type Plain struct {
	token string `glowy:"plain, second"`
}

func main() {
	// glowy::label::{secret}
	const secret = "hidden"

	plain := Plain(Classified{token: secret})

	// glowy::assert::{plain, second, secret}
	fmt.Println(plain.token)
}
