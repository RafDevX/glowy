package store

var Value any

var stored string

func Save(value string) {
	stored = value
}

func Load() string {
	return stored
}
