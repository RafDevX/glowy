package main

import "fmt"

type SourceColumn struct {
	Database string
}

type SourceColumnSet map[SourceColumn]bool

type query struct {
	defaultDatabase string
}

func main() {
	// glowy::label::{database}
	database := "private"

	q := query{defaultDatabase: database}

	makeSet := func() SourceColumnSet {
		return SourceColumnSet{
			{Database: q.defaultDatabase}: true,
		}
	}

	for column := range makeSet() {
		// glowy::assert::{database}
		fmt.Println(column.Database)
	}
}
