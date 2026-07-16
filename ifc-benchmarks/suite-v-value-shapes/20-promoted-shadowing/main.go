package main

import "fmt"

type Inner struct {
	Token string `glowy:"high"`
}

type Outer struct {
	Inner
	Token string
}

func main() {
	var outer Outer

	token := outer.Token

	// glowy::assert::{}
	fmt.Println(token)
}
