package main

import (
	"fmt"

	_ "blank-import/installer"
	"blank-import/registry"
)

func main() {
	observed := registry.Value

	// glowy::assert::{private}
	fmt.Println(observed)
}
