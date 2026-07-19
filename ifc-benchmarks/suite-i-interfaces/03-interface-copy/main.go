package main

import "fmt"

type record struct {
	value int
}

func (record) preserve() {}

type source interface{ preserve() }
type carrier interface{ preserve() }

func main() {
	// glowy::label::{private}
	classified := 42

	original := record{classified}

	var boxed source = original
	var copied carrier = boxed

	original.value = 0

	recovered := copied.(record)

	// glowy::assert::{private}
	fmt.Println(recovered.value)

	// glowy::assert::{}
	fmt.Println(original.value)
}
