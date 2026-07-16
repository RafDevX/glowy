package main

import "fmt"

type Buffer struct {
	data string
}

func (b *Buffer) Read(_ string) string {
	return b.data
}

func Read(_ string) string {
	return "public"
}

func main() {
	// glowy::label::{high}
	const secret = "hidden"

	buffer := &Buffer{data: secret}

	methodResult := buffer.Read("public")
	functionResult := Read(secret)

	// glowy::assert::{high}
	fmt.Println(methodResult)

	// glowy::assert::{}
	fmt.Println(functionResult)
}
