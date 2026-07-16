package sub

// glowy::label::{private}
const tag = "wrapped"

type Formatter struct{}

func New() Formatter {
	return Formatter{}
}

func (Formatter) Wrap(msg string) string {
	return tag + ": <" + msg + ">"
}
